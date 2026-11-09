"""Shared fixtures.

Database fixtures live here so tests/db, tests/executor and tests/mcp share one
migrated, seeded test database (mcpguard_test) and one random context key per
session. They are not autouse: the pure tests (tests/validator, tests/test_*.py)
never touch a database. The database test directories opt in via their own
conftest.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import AsyncIterator, Iterator
from typing import Any
from uuid import UUID

import psycopg
import pytest

from app.config import Limits
from app.context import sign_context
from app.db import Pools, make_pool
from app.executor import Executor, Validator
from app.validator import validate
from scripts.migrate import apply_migrations, install_context_key
from scripts.seed import seed
from tests.db.helpers import DbTestSettings, TokenFactory
from tests.support import ExecutorFactory


@pytest.fixture(scope="session")
def db_settings() -> DbTestSettings:
    return DbTestSettings()  # type: ignore[call-arg]


@pytest.fixture(scope="session")
def context_key() -> bytes:
    return secrets.token_bytes(32)


@pytest.fixture(scope="session")
def prepared_database(db_settings: DbTestSettings, context_key: bytes) -> None:
    url = db_settings.test_migrator_database_url.get_secret_value()
    apply_migrations(url)
    install_context_key(url, context_key)
    seed(url)


@pytest.fixture
def reader_url(db_settings: DbTestSettings) -> str:
    return db_settings.test_reader_database_url.get_secret_value()


@pytest.fixture
def reader(reader_url: str) -> Iterator[psycopg.Connection[Any]]:
    """A mcp_reader connection in autocommit mode; use conn.transaction() blocks."""
    with psycopg.connect(reader_url, autocommit=True) as conn:
        yield conn


@pytest.fixture
def migrator(db_settings: DbTestSettings) -> Iterator[psycopg.Connection[Any]]:
    url = db_settings.test_migrator_database_url.get_secret_value()
    with psycopg.connect(url, autocommit=True) as conn:
        yield conn


@pytest.fixture
def auditor(db_settings: DbTestSettings) -> Iterator[psycopg.Connection[Any]]:
    url = db_settings.test_auditor_database_url.get_secret_value()
    with psycopg.connect(url, autocommit=True) as conn:
        yield conn


@pytest.fixture
def token(context_key: bytes) -> TokenFactory:
    """token(tenant, user, **kw) -> a context token signed with the test key."""

    def make(tenant_id: UUID, user_id: UUID, **kwargs: Any) -> str:
        return sign_context(tenant_id=tenant_id, user_id=user_id, key=context_key, **kwargs)

    return make


@pytest.fixture
async def make_executor(
    db_settings: DbTestSettings, context_key: bytes
) -> AsyncIterator[ExecutorFactory]:
    """Build Executors on real pools against the test database; closed after the test."""
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


def pytest_asyncio_loop_factories(config: pytest.Config, item: pytest.Item) -> dict[str, Any]:
    """psycopg's async mode cannot use Windows' default ProactorEventLoop.

    SelectorEventLoop is also the default on Linux, so CI runs the same loop.
    """
    return {"selector": asyncio.SelectorEventLoop}
