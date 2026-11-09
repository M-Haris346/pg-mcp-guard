"""Two principals, one server process: no cross-tenant leak, ever.

Two eras of the protocol are exercised:
- modern (2026-07-28, the SDK client's default): no session id, every request
  stands alone, so the only identity is the request's bearer token;
- legacy (initialize handshake): a stateful session with Mcp-Session-Id, where
  the SDK also binds the session to the credential that created it.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx2
import pytest
from mcp.server import streamable_http_manager
from mcp.shared.exceptions import MCPError
from mcp_types.version import LATEST_HANDSHAKE_VERSION

from app.auth import Principal
from app.config import Limits
from scripts.seed import ACME, BOB, CAROL, GLOBEX
from tests.http_support import ACCEPT, ServerFactory, mcp_session, mint, rpc_result
from tests.support import ALICE_AT_ACME, BOB_AT_GLOBEX, last_audit

TENANT_SQL = "SELECT DISTINCT tenant_id FROM orders"


def _headers(
    token: str | None, session_id: str | None = None, version: str | None = None
) -> dict[str, str]:
    headers = {"Accept": ACCEPT, "Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if session_id is not None:
        headers["Mcp-Session-Id"] = session_id
    if version is not None:
        headers["Mcp-Protocol-Version"] = version
    return headers


async def _open_legacy_session(http: httpx2.AsyncClient, url: str, token: str) -> tuple[str, str]:
    response = await http.post(
        url,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": LATEST_HANDSHAKE_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "isolation-test", "version": "0"},
            },
        },
        headers=_headers(token),
    )
    assert response.status_code == 200, response.text
    session_id = response.headers["mcp-session-id"]
    version = rpc_result(response)["result"]["protocolVersion"]
    initialized = await http.post(
        url,
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers=_headers(token, session_id, version),
    )
    assert initialized.status_code == 202
    return session_id, version


async def _call(
    http: httpx2.AsyncClient,
    url: str,
    token: str | None,
    session_id: str,
    version: str,
    sql: str,
    request_id: int = 2,
) -> httpx2.Response:
    return await http.post(
        url,
        json={
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": "run_query", "arguments": {"sql": sql}},
        },
        headers=_headers(token, session_id, version),
    )


def _rows(response: httpx2.Response) -> list[list[Any]]:
    result = rpc_result(response)["result"]
    assert not result.get("isError"), result
    rows: list[list[Any]] = result["structuredContent"]["rows"]
    return rows


# --- concurrency -----------------------------------------------------------------


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_concurrent_calls_of_two_principals_never_mix(
    http_server: ServerFactory, mode: str
) -> None:
    # Pool of 2 connections shared by both principals; a generous acquire
    # timeout so the test measures isolation, not pool pressure. Any error
    # result (including "unavailable") fails the test.
    limits = Limits(pool_acquire_timeout_s=30.0)
    calls = 20
    async with (
        http_server(reader_max=2, limits=limits) as srv,
        mcp_session(srv.url, mint(ALICE_AT_ACME), mode=mode) as (alice, _),
        mcp_session(srv.url, mint(BOB_AT_GLOBEX), mode=mode) as (bob, _),
    ):
        jobs = [alice.call_tool("run_query", {"sql": TENANT_SQL}) for _ in range(calls)]
        jobs += [bob.call_tool("run_query", {"sql": TENANT_SQL}) for _ in range(calls)]
        results = await asyncio.gather(*jobs)

    errors = [r for r in results if r.is_error]
    assert errors == []
    tenants = [r.structured_content["rows"] for r in results if r.structured_content]
    assert tenants[:calls] == [[[str(ACME)]]] * calls
    assert tenants[calls:] == [[[str(GLOBEX)]]] * calls


# --- legacy sessions: reuse with another credential --------------------------------


@pytest.mark.parametrize(
    ("owner", "intruder"),
    [
        (mint(ALICE_AT_ACME), mint(BOB_AT_GLOBEX)),
        # Same user, other tenant: still another principal.
        (
            mint(Principal(user_id=CAROL, tenant_id=ACME)),
            mint(Principal(user_id=CAROL, tenant_id=GLOBEX)),
        ),
    ],
    ids=["alice_session_bob_token", "carol_acme_session_carol_globex_token"],
)
async def test_session_id_with_another_principals_token_is_not_found(
    http_server: ServerFactory, owner: str, intruder: str
) -> None:
    async with http_server() as srv, httpx2.AsyncClient() as http:
        session_id, version = await _open_legacy_session(http, srv.url, owner)
        assert _rows(await _call(http, srv.url, owner, session_id, version, TENANT_SQL)) == [
            [str(ACME)]
        ]

        stolen = await _call(http, srv.url, intruder, session_id, version, TENANT_SQL, 3)
        anonymous = await _call(http, srv.url, None, session_id, version, TENANT_SQL, 4)

    assert stolen.status_code == 404  # "as if the session did not exist"
    assert "tenant" not in stolen.text and str(ACME) not in stolen.text
    assert anonymous.status_code == 401


async def test_sdk_client_swapping_to_another_principal_mid_session_gets_nothing(
    http_server: ServerFactory,
) -> None:
    async with (
        http_server() as srv,
        mcp_session(srv.url, mint(ALICE_AT_ACME), mode="legacy") as (client, http),
    ):
        first = await client.call_tool("run_query", {"sql": TENANT_SQL})
        http.headers["Authorization"] = f"Bearer {mint(BOB_AT_GLOBEX)}"
        with pytest.raises(MCPError):
            await client.call_tool("run_query", {"sql": TENANT_SQL})
    assert first.structured_content is not None
    assert first.structured_content["rows"] == [[str(ACME)]]


# --- A: the per-request principal is the real guarantee -----------------------------


async def test_with_the_session_owner_check_off_the_request_token_still_decides(
    http_server: ServerFactory, migrator: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Disable the SDK's session-owner binding entirely: every credential now
    looks like the session's owner. Bob's token on alice's session must still
    see only Globex, and the audit row must name bob."""

    def everyone_is_the_owner(user: Any) -> dict[str, Any]:
        return {"client_id": "same", "issuer": None, "subject": None}

    monkeypatch.setattr(streamable_http_manager, "authorization_context", everyone_is_the_owner)

    async with http_server() as srv, httpx2.AsyncClient() as http:
        session_id, version = await _open_legacy_session(http, srv.url, mint(ALICE_AT_ACME))
        response = await _call(
            http,
            srv.url,
            mint(BOB_AT_GLOBEX),
            session_id,
            version,
            "SELECT DISTINCT tenant_id FROM orders /* t-owner-check-off */",
        )

    assert response.status_code == 200  # the owner check really is off
    assert _rows(response) == [[str(GLOBEX)]]
    row = last_audit(migrator, "t-owner-check-off")
    assert row is not None and row[:2] == (BOB, GLOBEX)


# --- B: the request's token is used, not the session creator's -----------------------


async def test_session_outlives_its_creating_token(http_server: ServerFactory) -> None:
    """Create the session with short-lived token A, continue with token B (same
    principal). After A expires, calls with B still work and A gets 401."""
    token_a = mint(ALICE_AT_ACME, ttl_seconds=2)
    token_b = mint(ALICE_AT_ACME, ttl_seconds=600)
    session_ids: set[str] = set()

    async def remember_session(response: httpx2.Response) -> None:
        if (sid := response.headers.get("mcp-session-id")) is not None:
            session_ids.add(sid)

    async with (
        http_server() as srv,
        mcp_session(srv.url, token_a, mode="legacy") as (client, http),
    ):
        http.event_hooks["response"].append(remember_session)
        http.headers["Authorization"] = f"Bearer {token_b}"
        before = await client.call_tool("run_query", {"sql": TENANT_SQL})

        await asyncio.sleep(3)  # token A is now expired
        after = await client.call_tool("run_query", {"sql": TENANT_SQL})

        (session_id,) = session_ids
        async with httpx2.AsyncClient() as raw:
            with_a = await _call(
                raw, srv.url, token_a, session_id, LATEST_HANDSHAKE_VERSION, TENANT_SQL, 9
            )

    assert before.structured_content is not None and after.structured_content is not None
    assert after.structured_content["rows"] == [[str(ACME)]]  # B works after A expired
    assert with_a.status_code == 401  # A is checked on its own request, and refused
