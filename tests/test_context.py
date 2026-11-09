from __future__ import annotations

import hashlib
import hmac
from uuid import UUID

import pytest

from app.context import MAX_TTL_SECONDS, sign_context

TENANT = UUID("11111111-1111-1111-1111-111111111111")
USER = UUID("22222222-2222-2222-2222-222222222222")
KEY = b"k" * 32


def test_token_format_and_signature() -> None:
    token = sign_context(tenant_id=TENANT, user_id=USER, key=KEY, ttl_seconds=60, now=1_000)

    version, tenant, user, exp, sig = token.split(".")
    assert (version, tenant, user, exp) == ("v1", str(TENANT), str(USER), "1060")
    expected = hmac.new(KEY, f"v1.{TENANT}.{USER}.1060".encode(), hashlib.sha256).hexdigest()
    assert sig == expected


def test_different_key_gives_different_signature() -> None:
    a = sign_context(tenant_id=TENANT, user_id=USER, key=KEY, now=1_000)
    b = sign_context(tenant_id=TENANT, user_id=USER, key=b"j" * 32, now=1_000)
    assert a.rsplit(".", 1)[0] == b.rsplit(".", 1)[0]
    assert a != b


@pytest.mark.parametrize("ttl", [0, -1, MAX_TTL_SECONDS + 1])
def test_rejects_ttl_outside_db_limit(ttl: int) -> None:
    with pytest.raises(ValueError, match="ttl_seconds"):
        sign_context(tenant_id=TENANT, user_id=USER, key=KEY, ttl_seconds=ttl)


def test_rejects_short_key() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        sign_context(tenant_id=TENANT, user_id=USER, key=b"short")
