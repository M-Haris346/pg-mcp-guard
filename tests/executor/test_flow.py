"""validate -> execute -> result, and principal isolation through the executor."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from app.executor import QueryResult, ToolError
from app.validator import Verdict, validate
from scripts.seed import ACME, GLOBEX, ORDERS
from tests.support import ALICE_AT_ACME, BOB_AT_GLOBEX, ExecutorFactory, last_audit


async def test_allowed_query_returns_only_the_principals_rows(
    make_executor: ExecutorFactory,
) -> None:
    executor = await make_executor()

    result = await executor.run_query(ALICE_AT_ACME, "SELECT tenant_id, status FROM orders")

    assert isinstance(result, QueryResult)
    assert result.columns == ["tenant_id", "status"]
    assert {row[0] for row in result.rows} == {str(ACME)}
    assert result.row_count == sum(o.tenant_id == ACME for o in ORDERS)
    assert (result.truncated, result.truncated_reason) == (False, None)


async def test_rejected_query_never_touches_a_reader_connection(
    make_executor: ExecutorFactory, migrator: Any
) -> None:
    # The reader pool is never opened: any attempt to use it would raise.
    executor = await make_executor(open_reader=False)

    result = await executor.run_query(ALICE_AT_ACME, "SELECT pg_sleep(1) /* t-rejected */")

    assert result == ToolError("function_not_allowed: pg_sleep")
    row = last_audit(migrator, "t-rejected")
    assert row is not None and row[4:6] == ("rejected", "function_not_allowed: pg_sleep")


async def test_validation_runs_off_the_event_loop(make_executor: ExecutorFactory) -> None:
    def slow_validator(sql: str) -> Verdict:
        time.sleep(0.5)  # blocking, as a pathological parse would be
        return validate(sql)

    executor = await make_executor(validator=slow_validator)
    ticks = 0

    async def ticker() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(0.02)
            ticks += 1

    task = asyncio.create_task(ticker())
    try:
        result = await executor.run_query(ALICE_AT_ACME, "SELECT 1")
    finally:
        task.cancel()
    assert isinstance(result, QueryResult)
    assert ticks >= 10  # the loop kept running during the 0.5 s validation


async def test_principals_are_isolated_on_a_reused_connection(
    make_executor: ExecutorFactory,
) -> None:
    executor = await make_executor(reader_max=1)  # same backend for both calls

    alice = await executor.run_query(ALICE_AT_ACME, "SELECT DISTINCT tenant_id FROM orders")
    bob = await executor.run_query(BOB_AT_GLOBEX, "SELECT DISTINCT tenant_id FROM orders")

    assert isinstance(alice, QueryResult) and alice.rows == [[str(ACME)]]
    assert isinstance(bob, QueryResult) and bob.rows == [[str(GLOBEX)]]
