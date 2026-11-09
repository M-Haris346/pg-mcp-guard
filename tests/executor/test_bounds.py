"""Bounded fetch: max_rows + 1 via the cursor, cell and response byte caps,
strict-JSON values."""

from __future__ import annotations

import json

from app.config import Limits
from app.executor import QueryResult, ToolError
from scripts.seed import ACME, ORDERS
from tests.executor.conftest import ALICE_AT_ACME, ExecutorFactory

SIX_ROWS_LAST_DIVIDES_BY_ZERO = "SELECT 1 / x FROM (VALUES (1), (1), (1), (1), (1), (0)) AS v(x)"


async def test_under_the_row_limit_is_not_truncated(make_executor: ExecutorFactory) -> None:
    executor = await make_executor(limits=Limits(max_rows=4))

    result = await executor.run_query(ALICE_AT_ACME, "SELECT id FROM orders")

    assert isinstance(result, QueryResult)
    assert result.row_count == sum(o.tenant_id == ACME for o in ORDERS) == 4
    assert (result.truncated, result.truncated_reason) == (False, None)


async def test_over_the_row_limit_is_truncated(make_executor: ExecutorFactory) -> None:
    executor = await make_executor(limits=Limits(max_rows=3))

    result = await executor.run_query(ALICE_AT_ACME, "SELECT id FROM orders")

    assert isinstance(result, QueryResult)
    assert result.row_count == 3
    assert (result.truncated, result.truncated_reason) == (True, "max_rows")


async def test_rows_past_max_rows_plus_one_are_never_fetched(
    make_executor: ExecutorFactory,
) -> None:
    # Row 6 divides by zero. With max_rows=3 the cursor fetches 4 rows, so the
    # error is never evaluated: the result is unbounded only on the server's
    # side of the cursor.
    executor = await make_executor(limits=Limits(max_rows=3))

    result = await executor.run_query(ALICE_AT_ACME, SIX_ROWS_LAST_DIVIDES_BY_ZERO)

    assert isinstance(result, QueryResult)
    assert result.rows == [[1], [1], [1]]
    assert result.truncated_reason == "max_rows"


async def test_control_the_same_query_does_fail_when_all_rows_are_fetched(
    make_executor: ExecutorFactory,
) -> None:
    executor = await make_executor(limits=Limits(max_rows=10))

    result = await executor.run_query(ALICE_AT_ACME, SIX_ROWS_LAST_DIVIDES_BY_ZERO)

    assert result == ToolError("query_error: division by zero")


async def test_small_cells_are_untouched(make_executor: ExecutorFactory) -> None:
    executor = await make_executor(limits=Limits(max_cell_bytes=64))

    result = await executor.run_query(ALICE_AT_ACME, "SELECT name FROM customers ORDER BY name")

    assert isinstance(result, QueryResult)
    assert result.truncated is False
    assert result.rows[0] == ["Contoso GmbH"]


async def test_oversized_cell_is_cut_to_the_cap(make_executor: ExecutorFactory) -> None:
    executor = await make_executor(limits=Limits(max_cell_bytes=50))

    result = await executor.run_query(
        ALICE_AT_ACME, "SELECT string_agg(c.name, ',') FROM customers c, products p"
    )

    assert isinstance(result, QueryResult)
    (cell,) = result.rows[0]
    assert isinstance(cell, str) and 0 < len(cell.encode()) <= 50
    assert (result.truncated, result.truncated_reason) == (True, "cell_bytes")


async def test_response_byte_cap_stops_adding_rows(make_executor: ExecutorFactory) -> None:
    # Each uuid cell is 38 bytes as JSON; the column list is 6.
    executor = await make_executor(limits=Limits(max_cell_bytes=64, max_response_bytes=100))

    result = await executor.run_query(ALICE_AT_ACME, "SELECT id FROM orders")

    assert isinstance(result, QueryResult)
    assert result.row_count == 2
    assert (result.truncated, result.truncated_reason) == (True, "response_bytes")


async def test_whole_result_fits_under_the_default_response_cap(
    make_executor: ExecutorFactory,
) -> None:
    executor = await make_executor()
    result = await executor.run_query(ALICE_AT_ACME, "SELECT * FROM order_summary")
    assert isinstance(result, QueryResult) and result.truncated is False


async def test_non_finite_numbers_serialise_as_strict_json(make_executor: ExecutorFactory) -> None:
    executor = await make_executor()

    result = await executor.run_query(
        ALICE_AT_ACME,
        "SELECT 'NaN'::float8, 'Infinity'::float8, '-Infinity'::float8,"
        " 'NaN'::numeric, 'Infinity'::numeric, '-Infinity'::numeric, 1.5::float8, 2.50::numeric",
    )

    assert isinstance(result, QueryResult)
    assert result.rows == [
        ["NaN", "Infinity", "-Infinity", "NaN", "Infinity", "-Infinity", 1.5, "2.50"]
    ]
    json.dumps(result.to_dict(), allow_nan=False)  # raises on NaN / Infinity floats


async def test_other_types_serialise_as_json(make_executor: ExecutorFactory) -> None:
    executor = await make_executor()

    result = await executor.run_query(
        ALICE_AT_ACME,
        "SELECT id, created_at, created_at::date, interval '1 day 2 hours', true, NULL,"
        " ARRAY[1, 2] FROM orders LIMIT 1",
    )

    assert isinstance(result, QueryResult)
    row = result.rows[0]
    assert all(isinstance(v, str) for v in row[:4])
    assert row[4:] == [True, None, [1, 2]]
    json.dumps(result.to_dict(), allow_nan=False)
