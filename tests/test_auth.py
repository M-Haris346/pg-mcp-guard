"""Principal token verification (pure: no database)."""

from __future__ import annotations

import time
from typing import Any
from uuid import UUID

import jwt
import pytest

from app.auth import HS256Verifier, InvalidToken, Principal, sign_token

SECRET = b"unit-test-secret-" + b"0123456789abcdef" * 3  # 64 bytes: no HS512 warning
USER = UUID("11111111-1111-1111-1111-111111111111")
TENANT = UUID("22222222-2222-2222-2222-222222222222")
ISS = AUD = "pg-mcp-guard"


def _verifier(**kwargs: Any) -> HS256Verifier:
    return HS256Verifier(SECRET, issuer=ISS, audience=AUD, **kwargs)


def _claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": str(USER),
        "tenant_id": str(TENANT),
        "iss": ISS,
        "aud": AUD,
        "iat": now,
        "exp": now + 600,
    }
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


def _encode(claims: dict[str, Any], *, key: bytes | None = SECRET, algorithm: str = "HS256") -> str:
    return jwt.encode(claims, key, algorithm=algorithm)


def test_valid_token_gives_the_principal_and_expiry() -> None:
    claims = _claims()
    verified = _verifier().verify(_encode(claims))
    assert verified.principal == Principal(user_id=USER, tenant_id=TENANT)
    assert verified.expires_at == claims["exp"]


def test_sign_token_round_trips() -> None:
    token = sign_token(
        SECRET,
        user_id=USER,
        tenant_id=TENANT,
        issuer=ISS,
        audience=AUD,
        issued_at=int(time.time()),
        ttl_seconds=60,
    )
    assert _verifier().verify(token).principal == Principal(USER, TENANT)


@pytest.mark.parametrize("token", [None, ""])
def test_missing_token(token: str | None) -> None:
    with pytest.raises(InvalidToken, match="missing"):
        _verifier().verify(token)


@pytest.mark.parametrize(
    ("token", "reason"),
    [
        (_encode(_claims(), key=b"x" * 40), "bad_signature"),
        (_encode(_claims(), algorithm="HS512"), "algorithm_not_allowed"),
        (_encode(_claims(), key=None, algorithm="none"), "algorithm_not_allowed"),
        (_encode(_claims(exp=int(time.time()) - 120)), "expired"),
        (_encode(_claims(nbf=int(time.time()) + 600)), "not_yet_valid"),
        (_encode(_claims(iat=int(time.time()) + 600, exp=int(time.time()) + 900)), "not_yet_valid"),
        (_encode(_claims(iss="someone-else")), "wrong_issuer"),
        (_encode(_claims(aud="another-service")), "wrong_audience"),
        (_encode(_claims(tenant_id=None)), "missing_claim: tenant_id"),
        (_encode(_claims(sub=None)), "missing_claim: sub"),
        (_encode(_claims(exp=None)), "missing_claim: exp"),
        (_encode(_claims(iat=None)), "missing_claim: iat"),
        (_encode(_claims(sub="alice")), "invalid_subject_or_tenant"),
        (_encode(_claims(tenant_id="acme")), "invalid_subject_or_tenant"),
        ("not.a.jwt", "malformed"),
        ("garbage", "malformed"),
    ],
    ids=[
        "wrong_key",
        "hs512",
        "alg_none",
        "expired",
        "nbf_in_future",
        "iat_in_future",
        "wrong_issuer",
        "wrong_audience",
        "no_tenant",
        "no_sub",
        "no_exp",
        "no_iat",
        "sub_not_uuid",
        "tenant_not_uuid",
        "three_parts_garbage",
        "garbage",
    ],
)
def test_rejected_tokens(token: str, reason: str) -> None:
    with pytest.raises(InvalidToken) as raised:
        _verifier().verify(token)
    assert raised.value.reason == reason


def test_lifetime_at_the_maximum_is_accepted() -> None:
    now = int(time.time())
    token = _encode(_claims(iat=now, exp=now + 12 * 3600))
    assert _verifier().verify(token).principal.user_id == USER


def test_lifetime_over_the_maximum_is_rejected() -> None:
    now = int(time.time())
    token = _encode(_claims(iat=now, exp=now + 12 * 3600 + 1))
    with pytest.raises(InvalidToken, match="lifetime_too_long"):
        _verifier().verify(token)


def test_maximum_lifetime_is_configurable() -> None:
    now = int(time.time())
    token = _encode(_claims(iat=now, exp=now + 600))
    with pytest.raises(InvalidToken, match="lifetime_too_long"):
        _verifier(max_lifetime_seconds=300).verify(token)


def test_short_secret_is_refused() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        HS256Verifier(b"short", issuer=ISS, audience=AUD)
