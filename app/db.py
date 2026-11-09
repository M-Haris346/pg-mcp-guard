"""Connection pools and the read-only transaction every model query runs in.

Two pools, two roles:
- reader  (mcp_reader):  runs model SQL. SELECT-only grants, RLS, role limits.
- auditor (mcp_auditor): INSERT into audit.tool_calls, nothing else.

Every connection is reset with DISCARD ALL when it goes back to the pool.
Model SQL can set session-level state (set_config(..., false), including
mcpguard.ctx) and take session advisory locks; without the reset these would
reach the next principal on that connection. If the reset fails, psycopg_pool
closes the connection instead of reusing it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from psycopg import AsyncConnection, sql
from psycopg_pool import AsyncConnectionPool

from app.auth import Principal
from app.config import Limits, Settings
from app.context import sign_context

Conn = AsyncConnection[tuple[Any, ...]]
Pool = AsyncConnectionPool[Conn]

# The signed context: set through ctx.set_context (migration 007), a SECURITY
# DEFINER function that sets mcpguard.ctx and nothing else. mcp_reader may not
# call set_config itself (bootstrap), so model SQL cannot change any setting.
# The token is only ever a bind parameter (rule 4).
SET_CONTEXT_SQL = "SELECT ctx.set_context(%s)"


def set_local_limits_sql(limits: Limits) -> sql.Composed:
    """SET LOCAL for the per-query limits, from validated positive integers only.

    client_connection_check_interval: if the executor closes the connection
    (hard deadline backstop), the backend notices within a second instead of
    running on until statement_timeout.
    """
    values = {
        "statement_timeout": limits.statement_timeout_ms,
        "lock_timeout": limits.lock_timeout_ms,
        "client_connection_check_interval": 1000,
    }
    for name, value in values.items():
        # bool is an int subclass: refuse it explicitly.
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{name} must be a positive integer (milliseconds)")
    statements: list[sql.Composable] = [
        sql.SQL("SET LOCAL {} = {}").format(sql.Identifier(name), sql.Literal(value))
        for name, value in values.items()
    ]
    statements.append(sql.SQL("SET LOCAL search_path = shop"))
    return sql.SQL("; ").join(statements)


@dataclass
class Pools:
    reader: Pool
    auditor: Pool

    async def close(self) -> None:
        await self.reader.close()
        await self.auditor.close()


async def configure_connection(conn: Conn) -> None:
    # Autocommit, so every transaction is explicit (conn.transaction()). No
    # automatic server-side prepares: DISCARD ALL drops them anyway.
    conn.prepare_threshold = None
    await conn.set_autocommit(True)


async def configure_reader_connection(conn: Conn) -> None:
    await configure_connection(conn)
    # psycopg then starts transactions with BEGIN READ ONLY; the role's
    # default_transaction_read_only is a second, independent layer.
    await conn.set_read_only(True)


async def discard_all(conn: Conn) -> None:
    await conn.execute("DISCARD ALL")


def make_pool(
    url: str,
    *,
    max_size: int,
    name: str,
    read_only: bool,
    reset: bool = True,
    open_timeout: float = 10.0,
) -> Pool:
    """reset=False exists only so a test can show what DISCARD ALL prevents."""
    return AsyncConnectionPool(
        url,
        min_size=1,
        max_size=max_size,
        name=name,
        open=False,
        configure=configure_reader_connection if read_only else configure_connection,
        reset=discard_all if reset else None,
        timeout=open_timeout,
    )


async def open_pools(settings: Settings) -> Pools:
    pools = Pools(
        reader=make_pool(
            settings.reader_database_url.get_secret_value(),
            max_size=settings.reader_pool_max,
            name="reader",
            read_only=True,
        ),
        auditor=make_pool(
            settings.auditor_database_url.get_secret_value(),
            max_size=settings.auditor_pool_max,
            name="auditor",
            read_only=False,
        ),
    )
    try:
        await pools.reader.open(wait=True, timeout=settings.pool_open_timeout_s)
        await pools.auditor.open(wait=True, timeout=settings.pool_open_timeout_s)
    except BaseException:
        await pools.close()
        raise
    return pools


@asynccontextmanager
async def read_only_transaction(
    conn: Conn, principal: Principal, context_key: bytes, limits: Limits
) -> AsyncIterator[Conn]:
    """BEGIN READ ONLY, set the signed context and limits, always ROLLBACK."""
    token = sign_context(tenant_id=principal.tenant_id, user_id=principal.user_id, key=context_key)
    async with conn.transaction(force_rollback=True):
        # No parameters: one simple-protocol round trip for all four SETs.
        await conn.execute(set_local_limits_sql(limits))
        await conn.execute(SET_CONTEXT_SQL, (token,))
        yield conn
