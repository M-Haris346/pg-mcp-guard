"""Application settings, read from the environment (and .env in development)."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.context import MIN_KEY_BYTES


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

    def context_key_bytes(self) -> bytes:
        return bytes.fromhex(self.mcp_context_key.get_secret_value())


@lru_cache
def get_settings() -> Settings:
    return Settings()  # required values come from the environment
