"""External cancellation: the caller cancels run_query (in Phase 4/5: MCP
notifications/cancelled, or an HTTP client disconnecting).

Expected: the CancelledError reaches the caller; the connection is closed,
never reused (a late cancel must not hit the next principal); the call is still
audited, with reason "cancelled"; nothing is left running. Validator OFF, so
pg_sleep reaches the database.
"""

from __future__ import annotations

import asyncio
import gc
import logging
import time
from typing import Any

import pytest

from app import executor as executor_module
from app.audit import AuditRecord
from app.db import Pool
from app.executor import AUDIT_TASK_NAME, QUERY_TASK_NAME, Executor, QueryResult
from tests.support import ALICE_AT_ACME, ExecutorFactory, allow_all, last_audit


async def _pid(executor: Executor) -> int:
    result = await executor.run_query(ALICE_AT_ACME, "SELECT pg_backend_pid()")
    assert isinstance(result, QueryResult)
    pid = result.rows[0][0]
    assert isinstance(pid, int)
    return pid


def _assert_nothing_left_running(caplog: pytest.LogCaptureFixture) -> None:
    pending = [
        t
        for t in asyncio.all_tasks()
        if t.get_name() in {QUERY_TASK_NAME, AUDIT_TASK_NAME} and not t.done()
    ]
    assert pending == []
    gc.collect()  # a pending task that was dropped would be reported now
    destroyed = [r for r in caplog.records if "Task was destroyed" in r.getMessage()]
    assert destroyed == []


@pytest.fixture
def slow_audit(monkeypatch: pytest.MonkeyPatch) -> asyncio.Event:
    """Make every audit write wait 0.3 s first; the event fires when one starts."""
    started = asyncio.Event()
    original = executor_module.write_audit

    async def write_audit(pool: Pool, record: AuditRecord, *, acquire_timeout_s: float) -> None:
        started.set()
        await asyncio.sleep(0.3)
        await original(pool, record, acquire_timeout_s=acquire_timeout_s)

    monkeypatch.setattr(executor_module, "write_audit", write_audit)
    return started


async def test_cancel_during_query(
    make_executor: ExecutorFactory, migrator: Any, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.ERROR, logger="asyncio")
    executor = await make_executor(validator=allow_all, reader_max=1)
    before = await _pid(executor)

    call = asyncio.create_task(executor.run_query(ALICE_AT_ACME, "SELECT pg_sleep(5) /* t-c1 */"))
    await asyncio.sleep(0.5)
    started = time.monotonic()
    call.cancel()
    with pytest.raises(asyncio.CancelledError):
        await call
    assert time.monotonic() - started < 2.0  # not psycopg's own 5 s interrupt path

    assert await _pid(executor) != before  # the connection was closed, not reused
    row = last_audit(migrator, "t-c1")
    assert row is not None and row[4:6] == ("error", "cancelled")
    _assert_nothing_left_running(caplog)


async def test_cancel_during_the_audit_write(
    make_executor: ExecutorFactory,
    migrator: Any,
    slow_audit: asyncio.Event,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR, logger="asyncio")
    executor = await make_executor(reader_max=1)

    call = asyncio.create_task(executor.run_query(ALICE_AT_ACME, "SELECT 1 /* t-c2 */"))
    await slow_audit.wait()  # the query is done; the audit write has begun
    call.cancel()
    with pytest.raises(asyncio.CancelledError):
        await call

    row = last_audit(migrator, "t-c2")
    assert row is not None and row[4] == "allowed"  # the shielded write completed
    assert isinstance(await executor.run_query(ALICE_AT_ACME, "SELECT 1"), QueryResult)
    _assert_nothing_left_running(caplog)


async def test_cancel_during_query_then_again_during_its_audit_write(
    make_executor: ExecutorFactory,
    migrator: Any,
    slow_audit: asyncio.Event,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR, logger="asyncio")
    executor = await make_executor(validator=allow_all, reader_max=1)
    before = await _pid(executor)
    slow_audit.clear()  # _pid's own audit write set it

    call = asyncio.create_task(executor.run_query(ALICE_AT_ACME, "SELECT pg_sleep(5) /* t-c3 */"))
    await asyncio.sleep(0.5)
    call.cancel()  # during the query
    await slow_audit.wait()
    call.cancel()  # and again, during the audit write
    with pytest.raises(asyncio.CancelledError):
        await call

    row = last_audit(migrator, "t-c3")
    assert row is not None and row[4:6] == ("error", "cancelled")
    assert await _pid(executor) != before
    _assert_nothing_left_running(caplog)


async def test_uncancelled_call_is_unaffected(make_executor: ExecutorFactory) -> None:
    executor = await make_executor(reader_max=1)
    assert isinstance(await executor.run_query(ALICE_AT_ACME, "SELECT 1"), QueryResult)
