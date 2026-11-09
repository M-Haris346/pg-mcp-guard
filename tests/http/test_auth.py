"""Bearer authentication on every request: 401s, their audit rows, the reason
holder, and what happens when the audit write is slow or fails."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx2
import jwt
import pytest

from app import http_transport
from app.auth import HS256Verifier
from app.http_transport import (
    AUTH_AUDIT_PER_MINUTE,
    AUTH_AUDIT_TIMEOUT_S,
    AuthOutcome,
    BearerTokenVerifier,
    _auth_outcome,
)
from scripts.seed import ACME, ALICE
from tests.http_support import (
    ACCEPT,
    AUDIENCE,
    ISSUER,
    JWT_SECRET,
    ServerFactory,
    mcp_session,
    mint,
)
from tests.support import ALICE_AT_ACME, MALLORY_AT_ACME

GENERIC_401 = {"error": "invalid_token", "error_description": "Authentication required"}
LIST_TOOLS = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}


def _max_audit_id(migrator: Any) -> int:
    row = migrator.execute("SELECT coalesce(max(id), 0) FROM audit.tool_calls").fetchone()
    return int(row[0])


async def _auth_rows(migrator: Any, after: int, expected: int, wait_s: float = 5.0) -> list[Any]:
    """http_auth rows written after id `after` (the write lands just after the 401)."""
    deadline = time.monotonic() + wait_s
    rows: list[Any] = []
    while time.monotonic() < deadline:
        rows = migrator.execute(
            "SELECT user_id, tenant_id, sql_text, verdict, reason FROM audit.tool_calls"
            " WHERE tool = 'http_auth' AND id > %s ORDER BY id",
            (after,),
        ).fetchall()
        if len(rows) >= expected:
            return rows
        await asyncio.sleep(0.05)
    return rows


def _claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    claims = {
        "sub": str(ALICE),
        "tenant_id": str(ACME),
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 600,
    }
    claims.update(overrides)
    return claims


BAD_TOKENS: dict[str, tuple[str | None, str]] = {
    "missing": (None, "missing_token"),
    "basic_scheme": ("Basic YWxpY2U6cGFzcw==", "missing_token"),
    "bad_signature": (
        "Bearer " + mint(ALICE_AT_ACME, secret=b"another-secret-of-at-least-32-bytes!!"),
        "bad_signature",
    ),
    "alg_none": (
        "Bearer " + jwt.encode(_claims(), None, algorithm="none"),
        "algorithm_not_allowed",
    ),
    "expired": (
        "Bearer " + mint(ALICE_AT_ACME, issued_at=int(time.time()) - 7200),
        "expired",
    ),
    "lifetime_too_long": (
        "Bearer " + mint(ALICE_AT_ACME, ttl_seconds=13 * 3600),
        "lifetime_too_long",
    ),
    "wrong_audience": (
        "Bearer " + jwt.encode(_claims(aud="other"), JWT_SECRET, algorithm="HS256"),
        "wrong_audience",
    ),
    "wrong_issuer": (
        "Bearer " + jwt.encode(_claims(iss="other"), JWT_SECRET, algorithm="HS256"),
        "wrong_issuer",
    ),
    "not_a_member": ("Bearer " + mint(MALLORY_AT_ACME), "not_a_member"),
    "garbage": ("Bearer not-a-jwt", "malformed"),
}


async def test_valid_token_is_accepted(http_server: ServerFactory) -> None:
    async with http_server() as srv, mcp_session(srv.url, mint(ALICE_AT_ACME)) as (client, _):
        result = await client.call_tool("run_query", {"sql": "SELECT 1"})
    assert not result.is_error


@pytest.mark.parametrize("case", BAD_TOKENS, ids=list(BAD_TOKENS))
async def test_bad_token_gets_a_generic_401_and_is_audited(
    http_server: ServerFactory, migrator: Any, case: str
) -> None:
    header, reason = BAD_TOKENS[case]
    headers = {"Accept": ACCEPT, "Content-Type": "application/json"}
    if header is not None:
        headers["Authorization"] = header
    async with http_server() as srv, httpx2.AsyncClient() as http:
        before = _max_audit_id(migrator)
        response = await http.post(srv.url, json=LIST_TOOLS, headers=headers)
        rows = await _auth_rows(migrator, before, expected=1)

    assert response.status_code == 401
    assert response.json() == GENERIC_401  # the client never learns why
    assert response.headers["www-authenticate"].startswith('Bearer error="invalid_token"')
    assert rows == [(None, None, None, "rejected", f"invalid_token: {reason}")]


async def test_a_token_that_expires_is_refused_on_the_next_request(
    http_server: ServerFactory,
) -> None:
    token = mint(ALICE_AT_ACME, ttl_seconds=2)
    async with http_server() as srv, mcp_session(srv.url, token) as (client, _):
        assert not (await client.call_tool("run_query", {"sql": "SELECT 1"})).is_error
        await asyncio.sleep(3)
        async with httpx2.AsyncClient() as http:
            response = await http.post(
                srv.url,
                json=LIST_TOOLS,
                headers={"Authorization": f"Bearer {token}", "Accept": ACCEPT},
            )
    assert response.status_code == 401


async def test_verifier_reports_the_reason_by_mutating_the_request_holder() -> None:
    async def never_called(principal: Any) -> bool:
        raise AssertionError("membership must not be checked for a bad token")

    verifier = BearerTokenVerifier(
        HS256Verifier(JWT_SECRET, issuer=ISSUER, audience=AUDIENCE),
        never_called,
        issuer=ISSUER,
        leeway_seconds=0,
    )
    holder = AuthOutcome()
    context_token = _auth_outcome.set(holder)
    try:
        result = await verifier.verify_token(mint(ALICE_AT_ACME, issued_at=int(time.time()) - 7200))
        assert _auth_outcome.get() is holder  # the verifier did not replace it
    finally:
        _auth_outcome.reset(context_token)
    assert result is None
    assert holder.reason == "expired"


async def test_verifier_without_a_holder_is_harmless() -> None:
    async def member(principal: Any) -> bool:
        return True

    verifier = BearerTokenVerifier(
        HS256Verifier(JWT_SECRET, issuer=ISSUER, audience=AUDIENCE),
        member,
        issuer=ISSUER,
        leeway_seconds=0,
    )
    assert await verifier.verify_token("garbage") is None  # no holder set: nothing to mutate


@pytest.mark.parametrize("failure", ["raises", "slow"])
async def test_audit_trouble_never_changes_the_401(
    http_server: ServerFactory, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    async def broken(*args: Any, **kwargs: Any) -> None:
        if failure == "raises":
            raise RuntimeError("audit database down")
        await asyncio.sleep(30)

    monkeypatch.setattr(http_transport, "write_auth_failure", broken)
    async with http_server() as srv, httpx2.AsyncClient() as http:
        started = time.monotonic()
        response = await http.post(srv.url, json=LIST_TOOLS, headers={"Accept": ACCEPT})
        elapsed = time.monotonic() - started
        # The server is still fine afterwards.
        async with mcp_session(srv.url, mint(ALICE_AT_ACME)) as (client, _):
            assert not (await client.call_tool("run_query", {"sql": "SELECT 1"})).is_error

    assert response.status_code == 401  # never 500
    assert response.json() == GENERIC_401
    assert elapsed < AUTH_AUDIT_TIMEOUT_S + 1.0  # bounded, not the 30 s write


async def test_401_audit_is_rate_limited(http_server: ServerFactory, migrator: Any) -> None:
    attempts = AUTH_AUDIT_PER_MINUTE + 15
    async with http_server() as srv, httpx2.AsyncClient() as http:
        before = _max_audit_id(migrator)
        for _ in range(attempts):
            response = await http.post(srv.url, json=LIST_TOOLS, headers={"Accept": ACCEPT})
            assert response.status_code == 401
        rows = await _auth_rows(migrator, before, expected=AUTH_AUDIT_PER_MINUTE)
        await asyncio.sleep(0.3)  # anything over the limit would have landed by now
        rows = await _auth_rows(migrator, before, expected=AUTH_AUDIT_PER_MINUTE)

    # The bucket refills at one per second while the requests run.
    assert AUTH_AUDIT_PER_MINUTE <= len(rows) < attempts
