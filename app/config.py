"""Application settings, read from the environment (and .env in development)."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Literal, Self

from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.context import MIN_KEY_BYTES

# Role-level limits set in db/bootstrap/00_bootstrap.sh. The per-query limits
# below must stay inside them.
ROLE_STATEMENT_TIMEOUT_MS = 5000
READER_CONNECTION_LIMIT = 10
AUDITOR_CONNECTION_LIMIT = 5


@dataclass(frozen=True)
class Limits:
    """Per-query limits enforced by the executor (ADR 0004)."""

    statement_timeout_ms: int = 3000
    lock_timeout_ms: int = 1000
    # Client-side deadline for the whole query (DECLARE + every FETCH). Longer
    # than statement_timeout, so normally the server times out first.
    deadline_ms: int = 4000
    # After the deadline: how long a server-side cancel may take before the
    # connection is closed to unblock the call.
    cancel_grace_ms: int = 2000
    max_rows: int = 100
    max_cell_bytes: int = 4096
    max_response_bytes: int = 262_144
    fetch_batch_rows: int = 50
    pool_acquire_timeout_s: float = 2.0

    def __post_init__(self) -> None:
        positive = {
            "statement_timeout_ms": self.statement_timeout_ms,
            "lock_timeout_ms": self.lock_timeout_ms,
            "deadline_ms": self.deadline_ms,
            "cancel_grace_ms": self.cancel_grace_ms,
            "max_rows": self.max_rows,
            "max_cell_bytes": self.max_cell_bytes,
            "max_response_bytes": self.max_response_bytes,
            "fetch_batch_rows": self.fetch_batch_rows,
            "pool_acquire_timeout_s": self.pool_acquire_timeout_s,
        }
        for name, value in positive.items():
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        # deadline_ms > statement_timeout_ms is enforced on Settings (startup),
        # not here, so tests can build a deadline that fires before the
        # server-side timeout and exercise the client-side cancel.
        if self.max_cell_bytes > self.max_response_bytes:
            raise ValueError("max_cell_bytes must not exceed max_response_bytes")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Defaults to "prod" so dev-only behaviour stays off unless explicitly enabled.
    app_env: Literal["dev", "test", "prod"] = "prod"

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # Runtime connections. The migrator URL is deliberately not here: the
    # server never needs owner privileges. SecretStr keeps passwords out of
    # reprs and logs. No defaults: a missing value is a startup error.
    reader_database_url: SecretStr
    auditor_database_url: SecretStr

    # Hex-encoded HMAC key for the signed RLS context (app/context.py).
    mcp_context_key: SecretStr

    # Executor limits (see Limits for meaning). Env: QUERY_STATEMENT_TIMEOUT_MS, ...
    query_statement_timeout_ms: int = Limits.statement_timeout_ms
    query_lock_timeout_ms: int = Limits.lock_timeout_ms
    query_deadline_ms: int = Limits.deadline_ms
    query_cancel_grace_ms: int = Limits.cancel_grace_ms
    max_rows: int = Limits.max_rows
    max_cell_bytes: int = Limits.max_cell_bytes
    max_response_bytes: int = Limits.max_response_bytes
    fetch_batch_rows: int = Limits.fetch_batch_rows
    pool_acquire_timeout_s: float = Limits.pool_acquire_timeout_s

    # Must stay below the roles' CONNECTION LIMITs.
    reader_pool_max: int = 4
    auditor_pool_max: int = 2
    # How long startup waits for the pools' first connections.
    pool_open_timeout_s: float = 10.0

    # Principal tokens (app/auth.py, ADR 0005). HS256 shared secret: demo only.
    jwt_secret: SecretStr
    jwt_issuer: str = "pg-mcp-guard"
    jwt_audience: str = "pg-mcp-guard"
    jwt_leeway_seconds: int = 30
    # exp - iat may not exceed this, however the token was signed.
    jwt_max_lifetime_seconds: int = 12 * 3600

    # stdio mode: the principal for the whole process. Verified at startup,
    # never logged. Empty or unset means "no principal": the server refuses to start.
    mcp_principal_token: SecretStr | None = None

    @field_validator("mcp_context_key")
    @classmethod
    def _key_is_long_hex(cls, value: SecretStr) -> SecretStr:
        try:
            raw = bytes.fromhex(value.get_secret_value())
        except ValueError:
            raise ValueError("MCP_CONTEXT_KEY must be hex") from None
        if len(raw) < MIN_KEY_BYTES:
            raise ValueError(f"MCP_CONTEXT_KEY must be at least {MIN_KEY_BYTES} bytes")
        return value

    @field_validator("jwt_secret")
    @classmethod
    def _jwt_secret_long_enough(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value().encode()) < 32:
            raise ValueError("JWT_SECRET must be at least 32 bytes")
        return value

    @model_validator(mode="after")
    def _limits_are_consistent(self) -> Self:
        self.limits()  # raises ValueError, reported as a ValidationError
        if self.query_deadline_ms <= self.query_statement_timeout_ms:
            raise ValueError("QUERY_DEADLINE_MS must be greater than QUERY_STATEMENT_TIMEOUT_MS")
        if self.query_statement_timeout_ms >= ROLE_STATEMENT_TIMEOUT_MS:
            raise ValueError("QUERY_STATEMENT_TIMEOUT_MS must be below the role statement_timeout")
        if not 1 <= self.reader_pool_max < READER_CONNECTION_LIMIT:
            raise ValueError(f"READER_POOL_MAX must be in 1..{READER_CONNECTION_LIMIT - 1}")
        if not 1 <= self.auditor_pool_max < AUDITOR_CONNECTION_LIMIT:
            raise ValueError(f"AUDITOR_POOL_MAX must be in 1..{AUDITOR_CONNECTION_LIMIT - 1}")
        if self.jwt_max_lifetime_seconds <= 0 or self.jwt_leeway_seconds < 0:
            raise ValueError("JWT lifetime must be positive and leeway non-negative")
        if self.pool_open_timeout_s <= 0:
            raise ValueError("POOL_OPEN_TIMEOUT_S must be positive")
        return self

    def jwt_secret_bytes(self) -> bytes:
        return self.jwt_secret.get_secret_value().encode()

    def context_key_bytes(self) -> bytes:
        return bytes.fromhex(self.mcp_context_key.get_secret_value())

    def limits(self) -> Limits:
        return Limits(
            statement_timeout_ms=self.query_statement_timeout_ms,
            lock_timeout_ms=self.query_lock_timeout_ms,
            deadline_ms=self.query_deadline_ms,
            cancel_grace_ms=self.query_cancel_grace_ms,
            max_rows=self.max_rows,
            max_cell_bytes=self.max_cell_bytes,
            max_response_bytes=self.max_response_bytes,
            fetch_batch_rows=self.fetch_batch_rows,
            pool_acquire_timeout_s=self.pool_acquire_timeout_s,
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()  # required values come from the environment
