"""Shared fixtures.

Database fixtures live here so tests/db and tests/executor share one migrated,
seeded test database (mcpguard_test) and one random context key per session.
They are not autouse: the pure tests (tests/validator, tests/test_*.py) never
touch a database. tests/db and tests/executor opt in via their own conftest.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Iterator
from typing import Any
from uuid import UUID

import psycopg
import pytest

from app.context import sign_context
from scripts.migrate import apply_migrations, install_context_key
from scripts.seed import seed
from tests.db.helpers import DbTestSettings, TokenFactory


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


def pytest_asyncio_loop_factories(config: pytest.Config, item: pytest.Item) -> dict[str, Any]:
    """psycopg's async mode cannot use Windows' default ProactorEventLoop.

    SelectorEventLoop is also the default on Linux, so CI runs the same loop.
    """
    return {"selector": asyncio.SelectorEventLoop}
