"""MCP tool tests through the SDK's in-memory client (no subprocess, real database)."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any

import pytest
from mcp import Client

from app.auth import Principal, VerifiedToken
from app.config import Limits
from app.executor import Validator
from app.server import create_server
from app.validator import validate
from tests.support import ALICE_AT_ACME, ExecutorFactory

ClientFactory = Callable[..., AbstractAsyncContextManager[Client]]


@pytest.fixture(autouse=True)
def _database(prepared_database: None) -> None:
    """Every MCP test needs the prepared test database."""


@pytest.fixture
def connect(make_executor: ExecutorFactory) -> ClientFactory:
    """connect(principal=..., ...) -> async context manager yielding a connected Client."""

    @asynccontextmanager
    async def factory(
        *,
        principal: Principal = ALICE_AT_ACME,
        expires_in: int = 3600,
        validator: Validator = validate,
        limits: Limits | None = None,
        clock: Callable[[], float] = time.time,
        **executor_kwargs: Any,
    ) -> AsyncIterator[Client]:
        executor = await make_executor(validator=validator, limits=limits, **executor_kwargs)
        identity = VerifiedToken(principal=principal, expires_at=int(time.time()) + expires_in)
        server = create_server(executor, identity, clock=clock)
        async with Client(server) as client:
            yield client

    return factory
