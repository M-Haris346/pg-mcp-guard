"""Resource limits on mcp_reader: timeouts, temp files, connections. Validator OFF."""

from __future__ import annotations

import time
from typing import Any

import psycopg
import pytest
from psycopg import errors


def test_fast_query_is_allowed(reader: psycopg.Connection[Any]) -> None:
    assert reader.execute("SELECT pg_sleep(0.1), 1").fetchone() == ("", 1)


@pytest.mark.attack
def test_statement_timeout_cancels_a_long_query(reader: psycopg.Connection[Any]) -> None:
    started = time.monotonic()
    with pytest.raises(errors.QueryCanceled, match="statement timeout"):
        reader.execute("SELECT pg_sleep(10)")
    assert time.monotonic() - started < 8  # role limit is 5s


def test_lock_timeout_stops_waiting_for_a_lock(
    reader: psycopg.Connection[Any], migrator: psycopg.Connection[Any]
) -> None:
    with migrator.transaction():
        migrator.execute("LOCK TABLE shop.orders IN ACCESS EXCLUSIVE MODE")
        started = time.monotonic()
        with pytest.raises(errors.LockNotAvailable):
            reader.execute("SELECT 1 FROM shop.orders LIMIT 1")
        assert time.monotonic() - started < 4  # role limit is 1s


@pytest.mark.attack
def test_temp_file_limit_holds_even_after_reader_disables_statement_timeout(
    reader: psycopg.Connection[Any],
) -> None:
    # The attacker turns off the (user-settable) statement timeout and makes
    # every sort spill to disk. temp_file_limit is superuser-only, so it still
    # applies.
    reader.execute("SET statement_timeout = 0")
    reader.execute("SET work_mem = '64kB'")
    with pytest.raises(errors.ConfigurationLimitExceeded, match="temp_file_limit"):
        reader.execute("SELECT md5(g::text) AS h FROM generate_series(1, 20000000) AS g ORDER BY h")


def test_connection_limit(reader_url: str, migrator: psycopg.Connection[Any]) -> None:
    limit_row = migrator.execute(
        "SELECT rolconnlimit FROM pg_roles WHERE rolname = 'mcp_reader'"
    ).fetchone()
    assert limit_row == (10,)

    opened: list[psycopg.Connection[Any]] = []
    try:
        with pytest.raises(psycopg.OperationalError, match="too many connections for role"):
            for _ in range(11):
                opened.append(psycopg.connect(reader_url))
        # Other tests' connections may still be closing, so allow fewer than 10.
        assert 1 <= len(opened) <= 10
    finally:
        for conn in opened:
            conn.close()
