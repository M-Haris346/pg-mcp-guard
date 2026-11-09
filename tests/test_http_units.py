"""Pure unit tests for app/http_transport.py helpers (no database, no server)."""

from __future__ import annotations

import time
from typing import Any
from uuid import UUID

import pytest

from app.auth import HS256Verifier, Principal, sign_token
from app.config import Settings
from app.executor import ToolError
from app.http_transport import (
    LOOPBACK_HOSTS,
    LOOPBACK_ORIGINS,
    BearerTokenVerifier,
    HttpOptions,
    TokenBucket,
    http_bind_problem,
    http_principal,
    is_loopback,
)

SECRET = b"unit-http-secret-0123456789abcdef0123456789"
ALICE = Principal(UUID(int=1), UUID(int=2))
BOB = Principal(UUID(int=3), UUID(int=4))


@pytest.mark.parametrize(
    ("host", "loopback"),
    [
        ("127.0.0.1", True),
        ("127.5.5.5", True),
        ("::1", True),
        ("[::1]", True),
        ("localhost", True),
        ("0.0.0.0", False),  # noqa: S104 - the point of the test
        ("192.0.2.10", False),
        ("example.com", False),
        ("localhost.example.com", False),
    ],
)
def test_is_loopback(host: str, loopback: bool) -> None:
    assert is_loopback(host) is loopback


def _settings(monkeypatch: pytest.MonkeyPatch, **env: str) -> Settings:
    base = {
        "READER_DATABASE_URL": "postgresql://r:p@localhost/db",
        "AUDITOR_DATABASE_URL": "postgresql://a:p@localhost/db",
        "MCP_CONTEXT_KEY": "ab" * 32,
        "JWT_SECRET": "j" * 32,
    }
    for name in ("MCP_HTTP_HOST", "MCP_HTTP_ALLOW_REMOTE", "MCP_HTTP_ALLOWED_HOSTS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("MCP_HTTP_ALLOWED_ORIGINS", raising=False)
    for name, value in (base | env).items():
        monkeypatch.setenv(name, value)
    return Settings(_env_file=None)  # type: ignore[call-arg]


def test_loopback_bind_needs_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(monkeypatch)
    assert settings.mcp_http_host == "127.0.0.1"
    assert http_bind_problem(settings) is None


def test_remote_bind_needs_opt_in_and_allowlists(monkeypatch: pytest.MonkeyPatch) -> None:
    remote = {"MCP_HTTP_HOST": "0.0.0.0"}  # noqa: S104
    assert (http_bind_problem(_settings(monkeypatch, **remote)) or "").startswith(
        "remote_bind_not_allowed"
    )
    opted_in = remote | {"MCP_HTTP_ALLOW_REMOTE": "true"}
    assert http_bind_problem(_settings(monkeypatch, **opted_in)) == (
        "remote_bind_needs_allowed_hosts_and_origins"
    )
    complete = opted_in | {
        "MCP_HTTP_ALLOWED_HOSTS": '["mcp.example.com:443"]',
        "MCP_HTTP_ALLOWED_ORIGINS": '["https://app.example.com"]',
    }
    settings = _settings(monkeypatch, **complete)
    assert http_bind_problem(settings) is None
    security = HttpOptions.from_settings(settings).transport_security()
    assert security.enable_dns_rebinding_protection is True
    assert security.allowed_hosts == ["mcp.example.com:443"]
    assert security.allowed_origins == ["https://app.example.com"]


def test_dns_rebinding_protection_is_always_on_for_loopback() -> None:
    security = HttpOptions(host="127.0.0.1").transport_security()
    assert security.enable_dns_rebinding_protection is True
    assert security.allowed_hosts == LOOPBACK_HOSTS
    assert security.allowed_origins == LOOPBACK_ORIGINS


def test_remote_host_without_allowlists_gets_empty_lists_not_open_ones() -> None:
    security = HttpOptions(host="0.0.0.0").transport_security()  # noqa: S104
    assert security.enable_dns_rebinding_protection is True
    assert security.allowed_hosts == [] and security.allowed_origins == []


def test_token_bucket() -> None:
    now = [0.0]
    bucket = TokenBucket(60, clock=lambda: now[0])
    assert all(bucket.take() for _ in range(60))
    assert not bucket.take()
    now[0] += 1.0  # one token per second
    assert bucket.take()
    assert not bucket.take()
    now[0] += 3600.0  # never more than the capacity
    assert sum(bucket.take() for _ in range(100)) == 60


def _token(principal: Principal) -> str:
    return sign_token(
        SECRET,
        user_id=principal.user_id,
        tenant_id=principal.tenant_id,
        issuer="iss",
        audience="aud",
        issued_at=int(time.time()),
        ttl_seconds=600,
    )


class _Membership:
    def __init__(self, answer: bool | ToolError = True) -> None:
        self.answer = answer
        self.calls: list[Principal] = []

    async def __call__(self, principal: Principal) -> bool | ToolError:
        self.calls.append(principal)
        return self.answer


def _verifier(membership: _Membership, clock: Any, **kwargs: Any) -> BearerTokenVerifier:
    return BearerTokenVerifier(
        HS256Verifier(SECRET, issuer="iss", audience="aud"),
        membership,
        issuer="iss",
        leeway_seconds=0,
        clock=clock,
        **kwargs,
    )


async def test_positive_membership_is_cached_for_its_ttl() -> None:
    now = [0.0]
    membership = _Membership(True)
    verifier = _verifier(membership, lambda: now[0], cache_seconds=30)

    assert await verifier.verify_token(_token(ALICE)) is not None
    assert await verifier.verify_token(_token(ALICE)) is not None
    assert len(membership.calls) == 1
    now[0] += 31
    assert await verifier.verify_token(_token(ALICE)) is not None
    assert len(membership.calls) == 2


async def test_non_membership_is_never_cached() -> None:
    membership = _Membership(False)
    verifier = _verifier(membership, time.monotonic)
    assert await verifier.verify_token(_token(ALICE)) is None
    assert await verifier.verify_token(_token(ALICE)) is None
    assert len(membership.calls) == 2


async def test_membership_cache_is_size_bounded() -> None:
    membership = _Membership(True)
    verifier = _verifier(membership, time.monotonic, cache_size=1)
    await verifier.verify_token(_token(ALICE))
    await verifier.verify_token(_token(BOB))  # evicts alice
    await verifier.verify_token(_token(ALICE))
    assert membership.calls == [ALICE, BOB, ALICE]


async def test_membership_check_failure_is_a_401_not_an_exception() -> None:
    async def broken(principal: Principal) -> bool:
        raise RuntimeError("database down")

    verifier = BearerTokenVerifier(
        HS256Verifier(SECRET, issuer="iss", audience="aud"),
        broken,
        issuer="iss",
        leeway_seconds=0,
    )
    assert await verifier.verify_token(_token(ALICE)) is None


async def test_access_token_carries_the_principal_and_tenant_in_subject() -> None:
    access = await _verifier(_Membership(True), time.monotonic).verify_token(_token(ALICE))
    assert access is not None
    assert access.subject == f"{ALICE.user_id}/{ALICE.tenant_id}"
    assert access.claims is not None
    assert access.claims["tenant_id"] == str(ALICE.tenant_id)


def test_http_principal_without_a_request_is_none() -> None:
    assert http_principal() is None
