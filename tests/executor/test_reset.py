"""Connections are reset with DISCARD ALL when they go back to the pool.

Model SQL (validator OFF) leaves session state behind. Two kinds:
- Session GUCs set with set_config(..., false): the executor always ends with
  ROLLBACK, and Postgres undoes GUC changes made in a rolled-back transaction,
  so these do not survive even without the reset (checked below).
- Session advisory locks: ROLLBACK does not release them. Only DISCARD ALL does.
"""

from __future__ import annotations

from typing import Any

from app.executor import Executor, QueryResult
from tests.support import ALICE_AT_ACME, ExecutorFactory, allow_all

LEAVE_STATE_BEHIND = (
    "SELECT pg_backend_pid(), set_config('statement_timeout', '0', false),"
    " set_config('mcpguard.ctx', 'left-behind', false),"
    " set_config('search_path', 'pg_catalog', false), pg_advisory_lock(42)"
)

INSPECT_SESSION = (
    "SELECT pg_backend_pid(), current_setting('statement_timeout'),"
    " coalesce(current_setting('mcpguard.ctx', true), ''), current_setting('search_path'),"
    " (SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid())"
)


async def _leave_state_and_inspect(executor: Executor) -> tuple[Any, ...]:
    result = await executor.run_query(ALICE_AT_ACME, LEAVE_STATE_BEHIND)
    assert isinstance(result, QueryResult)
    pid = result.rows[0][0]

    # Look at the session itself, outside any executor transaction (which
    # would set its own transaction-local values).
    async with executor.pools.reader.connection() as conn:
        row = await (await conn.execute(INSPECT_SESSION)).fetchone()
    assert row is not None
    assert row[0] == pid  # pool size 1: the same backend
    return tuple(row[1:])


async def test_discard_all_clears_session_state(make_executor: ExecutorFactory) -> None:
    executor = await make_executor(validator=allow_all, reader_max=1)

    state = await _leave_state_and_inspect(executor)

    assert state == ("5s", "", "shop", 0)  # role defaults, no context, no locks


async def test_without_the_reset_the_advisory_lock_leaks(make_executor: ExecutorFactory) -> None:
    # Shows the test above can detect a leak.
    executor = await make_executor(validator=allow_all, reader_max=1, reset=False)

    state = await _leave_state_and_inspect(executor)

    assert state[3] == 1  # the next principal would inherit the lock
    assert state[:3] == ("5s", "", "shop")  # GUCs: undone by the ROLLBACK
