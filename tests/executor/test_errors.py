"""Database errors map to model-readable reasons and never leak internals."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from app.config import Limits
from app.executor import QueryResult, ToolError
from tests.support import (
    ALICE_AT_ACME,
    UNREACHABLE_URL,
    ExecutorFactory,
    allow_all,
)
from tests.validator.corpus import load_corpus

INTERNAL_MARKERS = ("mcp_", "mcpguard", "private", "context_key", "audit")


async def test_granted_column_is_readable(make_executor: ExecutorFactory) -> None:
    executor = await make_executor()
    assert isinstance(
        await executor.run_query(ALICE_AT_ACME, "SELECT name FROM customers"), QueryResult
    )


@pytest.mark.parametrize(
    "sql",
    ["SELECT email FROM customers", "SELECT * FROM customers", "SELECT c::text FROM customers c"],
)
async def test_column_grant_maps_to_column_not_allowed(
    make_executor: ExecutorFactory, sql: str
) -> None:
    executor = await make_executor()  # validator ON: these pass it, the DB refuses
    assert await executor.run_query(ALICE_AT_ACME, sql) == ToolError("column_not_allowed")


async def test_lock_timeout(make_executor: ExecutorFactory, migrator: Any) -> None:
    executor = await make_executor()
    with migrator.transaction():
        migrator.execute("LOCK TABLE shop.orders IN ACCESS EXCLUSIVE MODE")
        result = await executor.run_query(ALICE_AT_ACME, "SELECT id FROM orders")
    assert result == ToolError("lock_timeout")


async def test_temp_file_limit_maps_to_resource_limit(make_executor: ExecutorFactory) -> None:
    executor = await make_executor(validator=allow_all)
    result = await executor.run_query(
        ALICE_AT_ACME, "SELECT md5(g::text) AS h FROM generate_series(1, 20000000) AS g ORDER BY h"
    )
    assert result == ToolError("resource_limit")


@pytest.mark.parametrize(
    ("sql", "reason"),
    [
        ("SELECT 1 / 0", "query_error: division by zero"),
        ("SELECT nosuch FROM orders", 'query_error: column "nosuch" does not exist'),
        ("SELECT 'abc'::int", 'query_error: invalid input syntax for type integer: "abc"'),
    ],
)
async def test_query_errors_carry_the_primary_message(
    make_executor: ExecutorFactory, sql: str, reason: str
) -> None:
    executor = await make_executor()
    assert await executor.run_query(ALICE_AT_ACME, sql) == ToolError(reason)


async def test_query_error_mentioning_internals_is_scrubbed(make_executor: ExecutorFactory) -> None:
    executor = await make_executor(validator=allow_all)
    # 'relation "private.nope" does not exist'
    result = await executor.run_query(ALICE_AT_ACME, "SELECT * FROM private.nope")
    assert result == ToolError("query_error")


async def test_unreachable_database_maps_to_unavailable(make_executor: ExecutorFactory) -> None:
    executor = await make_executor(
        reader_url=UNREACHABLE_URL, limits=Limits(pool_acquire_timeout_s=0.5)
    )
    assert await executor.run_query(ALICE_AT_ACME, "SELECT 1") == ToolError("unavailable")


REJECTED = [c for c in load_corpus() if c.verdict == "reject"]


async def test_no_reason_leaks_internals_even_with_the_validator_off(
    make_executor: ExecutorFactory,
) -> None:
    """Every attack in the corpus, straight to the database. Whatever fails,
    the reason must not name roles, the context GUC, private objects or the
    audit schema unless the model's own SQL did."""
    limits = Limits(statement_timeout_ms=500, deadline_ms=1000, cancel_grace_ms=1000)
    executor = await make_executor(validator=allow_all, limits=limits)
    leaks: list[tuple[str, str]] = []

    for case in REJECTED:
        result = await asyncio.wait_for(executor.run_query(ALICE_AT_ACME, case.sql), timeout=10)
        if isinstance(result, ToolError):
            for marker in INTERNAL_MARKERS:
                if marker in result.reason and marker not in case.sql:
                    leaks.append((case.id, result.reason))

    assert leaks == []
