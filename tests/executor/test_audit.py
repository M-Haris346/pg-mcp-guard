"""Every call is audited as mcp_auditor; if the audit write fails, no result."""

from __future__ import annotations

from typing import Any

import pytest

from app.config import Limits
from app.executor import QueryResult, ToolError
from scripts.seed import ACME, ALICE
from tests.db.helpers import DbTestSettings
from tests.support import (
    ALICE_AT_ACME,
    UNREACHABLE_URL,
    ExecutorFactory,
    allow_all,
    last_audit,
)


async def test_allowed_call_is_audited(make_executor: ExecutorFactory, migrator: Any) -> None:
    executor = await make_executor(limits=Limits(max_rows=2))

    result = await executor.run_query(ALICE_AT_ACME, "SELECT id FROM orders /* t-audit-ok */")

    assert isinstance(result, QueryResult)
    row = last_audit(migrator, "t-audit-ok")
    assert row is not None
    user_id, tenant_id, tool, sql_text, verdict, reason, row_count, truncated, duration_ms = row
    assert (user_id, tenant_id, tool) == (ALICE, ACME, "run_query")
    assert sql_text == "SELECT id FROM orders /* t-audit-ok */"
    assert (verdict, reason, row_count, truncated) == ("allowed", "max_rows", 2, True)
    assert duration_ms >= 0


async def test_failed_call_is_audited_as_error(
    make_executor: ExecutorFactory, migrator: Any
) -> None:
    executor = await make_executor()

    await executor.run_query(ALICE_AT_ACME, "SELECT email FROM customers /* t-audit-err */")

    row = last_audit(migrator, "t-audit-err")
    assert row is not None and row[4:8] == ("error", "column_not_allowed", None, None)


async def test_nul_in_sql_is_audited_escaped(make_executor: ExecutorFactory, migrator: Any) -> None:
    executor = await make_executor()

    result = await executor.run_query(ALICE_AT_ACME, "SELECT 1 /* t-audit-nul */\x00; DROP")

    assert result == ToolError("syntax_error: NUL character")
    row = last_audit(migrator, "t-audit-nul")
    assert row is not None and "\\x00" in row[3] and row[4] == "rejected"


async def test_audit_never_holds_result_data_or_the_token(
    make_executor: ExecutorFactory, migrator: Any
) -> None:
    executor = await make_executor()
    result = await executor.run_query(
        ALICE_AT_ACME, "SELECT name FROM customers /* t-audit-data */"
    )
    assert isinstance(result, QueryResult) and result.rows

    row = last_audit(migrator, "t-audit-data")
    assert row is not None
    stored = " ".join(str(v) for v in row)
    assert all(name not in stored for (name,) in result.rows)
    assert "v1." not in stored  # no context token

    columns = migrator.execute(
        "SELECT column_name FROM information_schema.columns"
        " WHERE table_schema = 'audit' AND table_name = 'tool_calls'"
    ).fetchall()
    assert {c for (c,) in columns} == {
        "id", "at", "user_id", "tenant_id", "tool", "sql_text", "verdict", "reason",
        "row_count", "truncated", "duration_ms",
    }  # fmt: skip


@pytest.mark.parametrize("sql", ["SELECT name FROM customers", "SELECT pg_sleep(1)"])
async def test_audit_failure_returns_no_result(
    make_executor: ExecutorFactory, db_settings: DbTestSettings, sql: str
) -> None:
    # The "auditor" pool connects as mcp_reader, which may not INSERT into the
    # audit table: the write fails, so even a successful query returns nothing.
    executor = await make_executor(
        auditor_url=db_settings.test_reader_database_url.get_secret_value()
    )

    assert await executor.run_query(ALICE_AT_ACME, sql) == ToolError("audit_unavailable")


async def test_unreachable_audit_database_returns_no_result(
    make_executor: ExecutorFactory,
) -> None:
    executor = await make_executor(
        auditor_url=UNREACHABLE_URL, limits=Limits(pool_acquire_timeout_s=0.5)
    )
    result = await executor.run_query(ALICE_AT_ACME, "SELECT name FROM customers")
    assert result == ToolError("audit_unavailable")


async def test_validator_off_attack_is_still_audited(
    make_executor: ExecutorFactory, migrator: Any
) -> None:
    executor = await make_executor(validator=allow_all)
    await executor.run_query(ALICE_AT_ACME, "SELECT * FROM shop.users /* t-audit-off */")
    row = last_audit(migrator, "t-audit-off")
    assert row is not None and row[4:6] == ("error", "column_not_allowed")
