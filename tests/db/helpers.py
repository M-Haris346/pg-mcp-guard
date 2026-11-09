from __future__ import annotations

from collections.abc import Callable
from typing import Any, LiteralString

import psycopg
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class DbTestSettings(BaseSettings):
    # Missing values fail the run (pydantic ValidationError); DB tests never
    # silently skip.
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    test_migrator_database_url: SecretStr
    test_reader_database_url: SecretStr
    test_auditor_database_url: SecretStr


# token(tenant_id, user_id, **sign_context_kwargs) -> signed context token
TokenFactory = Callable[..., str]


def query_as(
    conn: psycopg.Connection[Any], ctx: str | None, sql: LiteralString
) -> list[tuple[Any, ...]]:
    """Run sql in one transaction, with mcpguard.ctx set to ctx (if not None).

    The token goes in as a bind parameter, never into the SQL text.
    """
    with conn.transaction():
        if ctx is not None:
            conn.execute("SELECT set_config('mcpguard.ctx', %s, true)", (ctx,))
        return conn.execute(sql).fetchall()
