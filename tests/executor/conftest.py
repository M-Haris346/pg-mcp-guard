"""Executor integration tests: real pools, real roles, the shared test database."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import pytest

from app.auth import Principal
from app.config import Limits
from app.db import Pools, make_pool
from app.executor import Executor, Validator
from app.validator import Verdict, validate
from scripts.seed import ACME, ALICE, BOB, GLOBEX
from tests.db.helpers import DbTestSettings

ALICE_AT_ACME = Principal(user_id=ALICE, tenant_id=ACME)
BOB_AT_GLOBEX = Principal(user_id=BOB, tenant_id=GLOBEX)

# Port 1 on loopback: nothing listens, connections fail fast.
UNREACHABLE_URL = "postgresql://nobody:nothing@127.0.0.1:1/none?connect_timeout=1"


def allow_all(sql: str) -> Verdict:
    """Validator OFF: shows what the database and executor do on their own."""
    return Verdict(allowed=True)


ExecutorFactory = Callable[..., Awaitable[Executor]]


@pytest.fixture(autouse=True)
def _database(prepared_database: None) -> None:
    """Every executor test needs the prepared test database."""


@pytest.fixture
async def make_executor(
    db_settings: DbTestSettings, context_key: bytes
) -> AsyncIterator[ExecutorFactory]:
    created: list[Pools] = []

    async def factory(
        *,
        limits: Limits | None = None,
        validator: Validator = validate,
        reader_max: int = 2,
        reset: bool = True,
        reader_url: str | None = None,
        auditor_url: str | None = None,
        open_reader: bool = True,
    ) -> Executor:
        reader = make_pool(
            reader_url or db_settings.test_reader_database_url.get_secret_value(),
            max_size=reader_max,
            name="test-reader",
            read_only=True,
            reset=reset,
        )
        auditor = make_pool(
            auditor_url or db_settings.test_auditor_database_url.get_secret_value(),
            max_size=1,
            name="test-auditor",
            read_only=False,
        )
        # Pools pointed at a bad URL are opened without waiting, so the
        # failure shows up where the executor uses them.
        if open_reader:
            await reader.open(wait=reader_url is None)
        await auditor.open(wait=auditor_url is None)
        pools = Pools(reader=reader, auditor=auditor)
        created.append(pools)
        return Executor(
            pools=pools,
            context_key=context_key,
            limits=limits or Limits(),
            validator=validator,
        )

    yield factory
    for pools in created:
        await pools.close()


def last_audit(migrator: Any, marker: str) -> tuple[Any, ...] | None:
    """The newest audit row whose sql_text contains marker (read as migrator)."""
    row: tuple[Any, ...] | None = migrator.execute(
        "SELECT user_id, tenant_id, tool, sql_text, verdict, reason, row_count, truncated,"
        " duration_ms FROM audit.tool_calls WHERE strpos(sql_text, %s) > 0"
        " ORDER BY id DESC LIMIT 1",
        (marker,),
    ).fetchone()
    return row
