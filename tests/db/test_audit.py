"""Audit table: mcp_auditor may only append; mcp_reader may not touch it at all."""

from __future__ import annotations

from typing import Any, LiteralString

import psycopg
import pytest
from psycopg import errors

from scripts.seed import ACME, ALICE

INSERT: LiteralString = (
    "INSERT INTO audit.tool_calls"
    " (user_id, tenant_id, tool, sql_text, verdict, reason, row_count, truncated, duration_ms)"
    " VALUES (%s, %s, 'run_query', 'SELECT 1', 'allowed', NULL, 1, false, 3)"
)


def test_auditor_can_insert(
    auditor: psycopg.Connection[Any], migrator: psycopg.Connection[Any]
) -> None:
    before = migrator.execute("SELECT count(*) FROM audit.tool_calls").fetchone()
    auditor.execute(INSERT, (ALICE, ACME))
    after = migrator.execute("SELECT count(*) FROM audit.tool_calls").fetchone()
    assert before is not None and after == (before[0] + 1,)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM audit.tool_calls",
        "UPDATE audit.tool_calls SET verdict = 'allowed'",
        "DELETE FROM audit.tool_calls",
        "TRUNCATE audit.tool_calls",
        "INSERT INTO audit.tool_calls (tool, verdict, duration_ms)"
        " VALUES ('run_query', 'allowed', 1) RETURNING *",
    ],
)
def test_auditor_cannot_read_or_rewrite_history(
    auditor: psycopg.Connection[Any], sql: LiteralString
) -> None:
    with pytest.raises(errors.InsufficientPrivilege):
        auditor.execute(sql)


def test_auditor_cannot_read_shop_data(auditor: psycopg.Connection[Any]) -> None:
    with pytest.raises(errors.InsufficientPrivilege, match="permission denied for schema shop"):
        auditor.execute("SELECT * FROM shop.orders")


@pytest.mark.attack
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM audit.tool_calls",
        "INSERT INTO audit.tool_calls (tool, verdict, duration_ms)"
        " VALUES ('run_query', 'allowed', 1)",
    ],
)
def test_reader_cannot_touch_audit(reader: psycopg.Connection[Any], sql: LiteralString) -> None:
    # READ WRITE, so the only thing stopping the reader is the missing privilege.
    with (
        pytest.raises(errors.InsufficientPrivilege, match="permission denied for schema audit"),
        reader.transaction(),
    ):
        reader.execute("SET TRANSACTION READ WRITE")
        reader.execute(sql)


def test_audit_constraints_reject_bad_verdicts(auditor: psycopg.Connection[Any]) -> None:
    with pytest.raises(errors.CheckViolation):
        auditor.execute(
            "INSERT INTO audit.tool_calls (tool, verdict, duration_ms)"
            " VALUES ('run_query', 'maybe', 1)"
        )
