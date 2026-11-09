"""Read-only transaction, transaction-local limits, the signed context as a bind
parameter, and the extended protocol. Validator OFF where noted."""

from __future__ import annotations

import time
from typing import Any

import psycopg
import pytest

from app.executor import QueryResult, ToolError
from scripts.seed import ACME, ALICE
from tests.executor.conftest import ALICE_AT_ACME, ExecutorFactory, allow_all


async def test_transaction_local_settings(make_executor: ExecutorFactory) -> None:
    executor = await make_executor(validator=allow_all)

    result = await executor.run_query(
        ALICE_AT_ACME,
        "SELECT current_setting('transaction_read_only'), current_setting('statement_timeout'),"
        " current_setting('lock_timeout'), current_setting('search_path'),"
        " current_setting('client_connection_check_interval')",
    )

    assert isinstance(result, QueryResult)
    assert result.rows == [["on", "3s", "1s", "shop", "1s"]]


async def test_transaction_is_read_only_even_if_the_session_default_is_off(
    make_executor: ExecutorFactory,
) -> None:
    # Turn the role's default off on the pooled connection (no reset, so it
    # sticks): the executor's own BEGIN READ ONLY must still apply.
    executor = await make_executor(validator=allow_all, reader_max=1, reset=False)
    async with executor.pools.reader.connection() as conn:
        await conn.execute("SET default_transaction_read_only = off")

    # FOR SHARE fails with ReadOnlySqlTransaction only in a read-only
    # transaction; in a read-write one it would be a privilege error.
    result = await executor.run_query(ALICE_AT_ACME, "SELECT id FROM shop.orders FOR SHARE")

    assert result == ToolError("read_only")


async def test_statement_timeout_is_the_lower_per_query_value(
    make_executor: ExecutorFactory,
) -> None:
    executor = await make_executor(validator=allow_all)

    started = time.monotonic()
    result = await executor.run_query(ALICE_AT_ACME, "SELECT pg_sleep(10)")
    elapsed = time.monotonic() - started

    assert result == ToolError("query_timeout")
    # 3 s per-query limit, not the role's 5 s and not the 4 s client deadline.
    assert 2.5 < elapsed < 3.9


async def test_context_token_travels_only_as_a_bind_parameter(
    make_executor: ExecutorFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[tuple[str, Any]] = []

    def record(cls: Any) -> None:
        original = cls.execute

        async def execute(self: Any, query: Any, params: Any = None, **kwargs: Any) -> Any:
            sent.append((str(query), params))
            return await original(self, query, params, **kwargs)

        monkeypatch.setattr(cls, "execute", execute)

    record(psycopg.AsyncCursor)
    record(psycopg.AsyncServerCursor)
    executor = await make_executor()

    result = await executor.run_query(ALICE_AT_ACME, "SELECT id FROM orders")

    assert isinstance(result, QueryResult)
    tokens = [
        p
        for _, params in sent
        for p in (params or ())
        if isinstance(p, str) and p.startswith(f"v1.{ACME}.{ALICE}.")
    ]
    assert len(tokens) == 1  # sent once, as a parameter
    for query, _ in sent:
        assert tokens[0] not in query
        assert str(ACME) not in query and "v1." not in query


@pytest.mark.parametrize(
    ("attack", "reason"),
    [
        # Extended protocol: Postgres refuses a second statement.
        ("SELECT 1; DROP TABLE shop.orders", "multiple_statements"),
        # DECLARE ... CURSOR FOR must be followed by a query, so the COMMIT
        # escape fails even earlier, as a syntax error.
        ("COMMIT; DROP TABLE shop.orders", 'query_error: syntax error at or near "COMMIT"'),
    ],
)
async def test_multiple_statements_are_refused_by_the_protocol(
    make_executor: ExecutorFactory, migrator: Any, attack: str, reason: str
) -> None:
    executor = await make_executor(validator=allow_all)

    result = await executor.run_query(ALICE_AT_ACME, attack)

    assert result == ToolError(reason)
    assert migrator.execute("SELECT to_regclass('shop.orders')").fetchone() == ("shop.orders",)


async def test_single_statement_runs(make_executor: ExecutorFactory) -> None:
    executor = await make_executor(validator=allow_all)
    assert isinstance(await executor.run_query(ALICE_AT_ACME, "SELECT 1"), QueryResult)
