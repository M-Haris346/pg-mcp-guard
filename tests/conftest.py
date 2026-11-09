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
import socket
import time
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID

import psycopg
import pytest
import uvicorn

from app.auth import HS256Verifier
from app.config import Limits
from app.context import sign_context
from app.db import Pools, make_pool
from app.executor import Executor, Validator
from app.http_transport import BearerTokenVerifier, HttpOptions, build_http_app, uvicorn_config
from app.validator import validate
from scripts.migrate import apply_migrations, install_context_key
from scripts.seed import seed
from tests.db.helpers import DbTestSettings, TokenFactory
from tests.http_support import AUDIENCE, ISSUER, JWT_SECRET, RunningServer, ServerFactory
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


@pytest.fixture
def http_server(make_executor: ExecutorFactory) -> ServerFactory:
    """http_server(...) -> async context manager yielding a RunningServer."""

    @asynccontextmanager
    async def factory(
        *,
        validator: Validator = validate,
        limits: Limits | None = None,
        reader_max: int = 2,
        auditor_url: str | None = None,
        membership_cache_s: float = 30.0,
        clock: Callable[[], float] = time.time,
        **options: Any,
    ) -> AsyncIterator[RunningServer]:
        executor = await make_executor(
            validator=validator, limits=limits, reader_max=reader_max, auditor_url=auditor_url
        )
        verifier = BearerTokenVerifier(
            HS256Verifier(JWT_SECRET, issuer=ISSUER, audience=AUDIENCE, leeway_seconds=0),
            executor.is_member,
            issuer=ISSUER,
            leeway_seconds=0,
            cache_seconds=membership_cache_s,
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        http_options = HttpOptions(host="127.0.0.1", port=port, **options)
        app = build_http_app(executor, verifier, http_options, leeway_seconds=0, clock=clock)
        server = uvicorn.Server(uvicorn_config(app, http_options))
        task = asyncio.create_task(server.serve(sockets=[sock]))
        try:
            while not server.started:
                if task.done():
                    task.result()  # surface a startup error
                await asyncio.sleep(0.01)
            yield RunningServer(
                url=f"http://127.0.0.1:{port}{http_options.path}",
                port=port,
                executor=executor,
                verifier=verifier,
            )
        finally:
            server.should_exit = True
            await asyncio.wait_for(task, timeout=15)
            sock.close()

    return factory


def pytest_asyncio_loop_factories(config: pytest.Config, item: pytest.Item) -> dict[str, Any]:
    """psycopg's async mode cannot use Windows' default ProactorEventLoop.

    SelectorEventLoop is also the default on Linux, so CI runs the same loop.
    """
    return {"selector": asyncio.SelectorEventLoop}
