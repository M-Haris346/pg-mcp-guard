"""MCP tool tests, run twice: through the SDK's in-memory client, and over real
Streamable HTTP (uvicorn in this process) with a bearer token per request.

The same assertions hold on both transports: strict inputs, exact reasons,
the untrusted-data fence, per-call expiry, cancellation, audit.
"""

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
from tests.http_support import ServerFactory, mcp_session, mint
from tests.support import ALICE_AT_ACME, ExecutorFactory

ClientFactory = Callable[..., AbstractAsyncContextManager[Client]]


@pytest.fixture(autouse=True)
def _database(prepared_database: None) -> None:
    """Every MCP test needs the prepared test database."""


@pytest.fixture(params=["memory", "http"])
def transport(request: pytest.FixtureRequest) -> str:
    value: str = request.param
    return value


@pytest.fixture
def connect(
    transport: str, make_executor: ExecutorFactory, http_server: ServerFactory
) -> ClientFactory:
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
        if transport == "memory":
            executor = await make_executor(validator=validator, limits=limits, **executor_kwargs)
            identity = VerifiedToken(principal=principal, expires_at=int(time.time()) + expires_in)
            async with Client(create_server(executor, identity, clock=clock)) as client:
                yield client
            return

        async with (
            http_server(validator=validator, limits=limits, clock=clock, **executor_kwargs) as srv,
            mcp_session(srv.url, mint(principal, ttl_seconds=expires_in)) as (client, _),
        ):
            yield client

    return factory
