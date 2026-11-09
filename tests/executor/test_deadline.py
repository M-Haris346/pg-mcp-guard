"""Client-side deadline, server-side cancel, the hard backstop, and the cancel
race (a late cancel must never reach another principal's query). Validator OFF:
the validator would reject pg_sleep before the database ever saw it."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import psycopg
import pytest

from app.config import Limits
from app.executor import QUERY_TASK_NAME, Executor, QueryResult, ToolError
from scripts.seed import GLOBEX
from tests.support import ALICE_AT_ACME, BOB_AT_GLOBEX, ExecutorFactory, allow_all

# Server-side timeout far away, so only the client-side deadline can fire.
DEADLINE_FIRST = Limits(statement_timeout_ms=30_000, deadline_ms=1000, cancel_grace_ms=2000)


async def _pid(executor: Executor) -> int:
    result = await executor.run_query(ALICE_AT_ACME, "SELECT pg_backend_pid()")
    assert isinstance(result, QueryResult)
    pid = result.rows[0][0]
    assert isinstance(pid, int)
    return pid


async def test_query_inside_the_deadline_returns(make_executor: ExecutorFactory) -> None:
    executor = await make_executor(validator=allow_all, limits=DEADLINE_FIRST)
    result = await executor.run_query(ALICE_AT_ACME, "SELECT pg_sleep(0.2), 1")
    assert isinstance(result, QueryResult) and result.rows == [["", 1]]


async def test_deadline_cancels_on_the_server(make_executor: ExecutorFactory) -> None:
    executor = await make_executor(validator=allow_all, limits=DEADLINE_FIRST, reader_max=1)

    started = time.monotonic()
    result = await executor.run_query(ALICE_AT_ACME, "SELECT pg_sleep(5)")
    elapsed = time.monotonic() - started

    assert result == ToolError("query_timeout")
    assert elapsed < 2.0  # deadline 1 s + the cancel round trip

    # The next call answers promptly: the server really stopped.
    started = time.monotonic()
    assert isinstance(await executor.run_query(ALICE_AT_ACME, "SELECT 1"), QueryResult)
    assert time.monotonic() - started < 1.0


async def test_deadline_also_covers_time_between_fetches(make_executor: ExecutorFactory) -> None:
    # Each FETCH is quick (one 0.3 s row, far below statement_timeout), but the
    # whole query is not. Only the client-side deadline sees the total.
    limits = Limits(deadline_ms=1000, fetch_batch_rows=1)
    executor = await make_executor(validator=allow_all, limits=limits)

    result = await executor.run_query(
        ALICE_AT_ACME,
        "SELECT pg_sleep(0.3)"
        " FROM (VALUES (1), (2), (3), (4), (5), (6), (7), (8), (9), (10)) AS v(x)",
    )

    assert result == ToolError("query_timeout")


async def test_a_timed_out_connection_is_never_reused(make_executor: ExecutorFactory) -> None:
    executor = await make_executor(validator=allow_all, limits=DEADLINE_FIRST, reader_max=1)
    before = await _pid(executor)

    assert await executor.run_query(ALICE_AT_ACME, "SELECT pg_sleep(5)") == ToolError(
        "query_timeout"
    )

    assert await _pid(executor) != before


async def test_the_query_task_is_done_before_the_connection_is_released(
    make_executor: ExecutorFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    executor = await make_executor(validator=allow_all, limits=DEADLINE_FIRST)
    pending_at_release: list[int] = []
    original_putconn = executor.pools.reader.putconn

    async def putconn(conn: Any) -> None:
        pending = [
            t for t in asyncio.all_tasks() if t.get_name() == QUERY_TASK_NAME and not t.done()
        ]
        pending_at_release.append(len(pending))
        await original_putconn(conn)

    monkeypatch.setattr(executor.pools.reader, "putconn", putconn)

    await executor.run_query(ALICE_AT_ACME, "SELECT 1")  # normal path
    await executor.run_query(ALICE_AT_ACME, "SELECT pg_sleep(5)")  # timeout path

    assert pending_at_release == [0, 0]


async def test_timeout_then_another_principals_query_is_not_cancelled(
    make_executor: ExecutorFactory,
) -> None:
    # Pool size 1: if the timed-out connection (or a late cancel) were
    # reused, bob's query would be the one cancelled.
    executor = await make_executor(validator=allow_all, limits=DEADLINE_FIRST, reader_max=1)

    alice = await executor.run_query(ALICE_AT_ACME, "SELECT pg_sleep(5)")
    bob = await executor.run_query(BOB_AT_GLOBEX, "SELECT DISTINCT tenant_id FROM orders")

    assert alice == ToolError("query_timeout")
    assert isinstance(bob, QueryResult) and bob.rows == [[str(GLOBEX)]]


async def test_hard_backstop_when_the_server_ignores_the_cancel(
    make_executor: ExecutorFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def ignored(self: Any, **kwargs: Any) -> None:
        return None  # as if the cancel request never arrived

    monkeypatch.setattr(psycopg.AsyncConnection, "cancel_safe", ignored)
    limits = Limits(statement_timeout_ms=30_000, deadline_ms=1000, cancel_grace_ms=1000)
    executor = await make_executor(validator=allow_all, limits=limits, reader_max=1)
    before = await _pid(executor)

    started = time.monotonic()
    result = await executor.run_query(ALICE_AT_ACME, "SELECT pg_sleep(10)")
    elapsed = time.monotonic() - started

    assert result == ToolError("query_timeout")
    assert elapsed < (limits.deadline_ms + limits.cancel_grace_ms) / 1000 + 1.0
    assert await _pid(executor) != before  # the connection was discarded
