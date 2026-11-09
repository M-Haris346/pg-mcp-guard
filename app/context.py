"""Sign the identity context that RLS policies trust (CLAUDE.md rule 4, ADR 0002).

Format, which must match ctx.current_tenant_id() (created in
db/migrations/002_rls_helper.sql, moved to ctx by 007):

    v1.<tenant_uuid>.<user_uuid>.<exp_unix_seconds>.<hex HMAC-SHA256 of the first four parts>

Only the database verifies tokens. The token is always sent to Postgres as a
bind parameter, never interpolated into SQL text (it would otherwise be visible
in query logs and statistics).
"""

from __future__ import annotations

import hashlib
import hmac
import time
from uuid import UUID

CONTEXT_VERSION = "v1"
# Must not exceed max_ttl_seconds in the database helper, which rejects
# tokens that expire further in the future than that.
MAX_TTL_SECONDS = 300
DEFAULT_TTL_SECONDS = 60
MIN_KEY_BYTES = 32


def sign_context(
    *,
    tenant_id: UUID,
    user_id: UUID,
    key: bytes,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now: int | None = None,
) -> str:
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(f"context key must be at least {MIN_KEY_BYTES} bytes")
    if not 0 < ttl_seconds <= MAX_TTL_SECONDS:
        raise ValueError(f"ttl_seconds must be in 1..{MAX_TTL_SECONDS}")

    issued_at = int(time.time()) if now is None else now
    # str(UUID) is the canonical lower-case form the database regex expects.
    payload = f"{CONTEXT_VERSION}.{tenant_id}.{user_id}.{issued_at + ttl_seconds}"
    signature = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"
