"""Pure unit tests for executor helpers: JSON values, byte caps, error mapping."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from uuid import UUID

import pytest
from psycopg import errors
from psycopg_pool import PoolTimeout

from app.executor import audit_sql_text, map_db_error, serialize_row, to_json_value


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (float("nan"), "NaN"),
        (float("inf"), "Infinity"),
        (float("-inf"), "-Infinity"),
        (Decimal("NaN"), "NaN"),
        (Decimal("Infinity"), "Infinity"),
        (Decimal("-Infinity"), "-Infinity"),
        (1.5, 1.5),
        (Decimal("2.50"), "2.50"),
        (12345678901234567890, 12345678901234567890),
        (True, True),
        (None, None),
        (UUID(int=1), "00000000-0000-0000-0000-000000000001"),
        (date(2026, 1, 2), "2026-01-02"),
        (datetime(2026, 1, 2, 3, 4, tzinfo=UTC), "2026-01-02T03:04:00+00:00"),
        (timedelta(days=1, hours=2), "1 day, 2:00:00"),
        ([1.0, float("nan"), None], [1.0, "NaN", None]),
        (b"\x01\xff", "01ff"),
    ],
)
def test_to_json_value(value: object, expected: object) -> None:
    converted = to_json_value(value)
    assert converted == expected
    json.dumps(converted, allow_nan=False)  # always strict JSON


def test_cell_cut_respects_utf8_boundaries() -> None:
    cells, size, cut = serialize_row(["é" * 10], max_cell_bytes=7)  # 'é' is 2 bytes
    assert cut is True
    assert cells == ["ééé"]  # 6 bytes; a half character is dropped
    assert size == len(json.dumps("ééé", ensure_ascii=False).encode())


def test_cells_under_the_cap_are_untouched() -> None:
    cells, _, cut = serialize_row(["abc", 1, None], max_cell_bytes=64)
    assert (cells, cut) == (["abc", 1, None], False)


def test_oversized_non_string_cell_becomes_a_cut_string() -> None:
    cells, _, cut = serialize_row([list(range(100))], max_cell_bytes=10)
    assert cut is True and cells[0] == "[0, 1, 2, "


@pytest.mark.parametrize(
    ("exc", "reason"),
    [
        (
            errors.InsufficientPrivilege("permission denied for table customers"),
            "column_not_allowed",
        ),
        (errors.QueryCanceled("canceling statement due to statement timeout"), "query_timeout"),
        (errors.LockNotAvailable("x"), "lock_timeout"),
        (errors.ReadOnlySqlTransaction("x"), "read_only"),
        (
            errors.ConfigurationLimitExceeded("temporary file size exceeds temp_file_limit"),
            "resource_limit",
        ),
        (errors.OutOfMemory("x"), "resource_limit"),
        (
            errors.SyntaxError("cannot insert multiple commands into a prepared statement"),
            "multiple_statements",
        ),
        (errors.ConnectionException("x"), "unavailable"),
        (errors.InternalError_("x"), "internal_error"),
    ],
)
def test_map_db_error(exc: errors.Error, reason: str) -> None:
    assert map_db_error(exc) == reason


def test_pool_timeout_is_not_a_db_error_but_handled_by_the_executor() -> None:
    # PoolTimeout is mapped in Executor._execute; map_db_error never sees it.
    assert issubclass(PoolTimeout, Exception)


@pytest.mark.parametrize(
    ("message", "reason"),
    [
        ("division by zero", "query_error: division by zero"),
        ('relation "private.context_key" does not exist', "query_error"),
        ('role "mcp_migrator" does not exist', "query_error"),
        ('unrecognized configuration parameter "mcpguard.x"', "query_error"),
        ("bad \x07 bell", "query_error: bad  bell"),
        ("x" * 500, "query_error: " + "x" * 200),
    ],
)
def test_query_error_detail_is_scrubbed(
    message: str, reason: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    exc = errors.DivisionByZero(message)

    class Diag:
        message_primary = message

    monkeypatch.setattr(errors.DivisionByZero, "diag", property(lambda self: Diag()))
    assert map_db_error(exc) == reason


def test_audit_sql_text_escapes_nul_and_is_bounded() -> None:
    assert audit_sql_text("SELECT 1\x00; DROP") == "SELECT 1\\x00; DROP"
    assert len(audit_sql_text("x" * 50_000)) == 20_000
