"""Application settings, read from the environment (and .env in development)."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Defaults to "prod" so dev-only behaviour stays off unless explicitly enabled.
    app_env: Literal["dev", "test", "prod"] = "prod"

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # Database, JWT and limit settings are added in the phase that uses them.


@lru_cache
def get_settings() -> Settings:
    return Settings()
