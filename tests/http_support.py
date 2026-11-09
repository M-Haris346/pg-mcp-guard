"""Helpers for the HTTP tests (the http_server fixture lives in tests/conftest.py).

Tests talk to a real uvicorn server with the SDK's own HTTP client stack
(httpx2, the httpx fork the mcp SDK depends on) or raw httpx2 requests.
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from app.auth import Principal, sign_token
from app.executor import Executor
from app.http_transport import BearerTokenVerifier

JWT_SECRET = b"http-test-jwt-secret-0123456789abcdef0123456789"
ISSUER = AUDIENCE = "pg-mcp-guard"
ACCEPT = "application/json, text/event-stream"


def mint(
    principal: Principal,
    *,
    ttl_seconds: int = 600,
    issued_at: int | None = None,
    secret: bytes = JWT_SECRET,
) -> str:
    return sign_token(
        secret,
        user_id=principal.user_id,
        tenant_id=principal.tenant_id,
        issuer=ISSUER,
        audience=AUDIENCE,
        issued_at=int(time.time()) if issued_at is None else issued_at,
        ttl_seconds=ttl_seconds,
    )


@dataclass
class RunningServer:
    url: str
    port: int
    executor: Executor
    verifier: BearerTokenVerifier
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"


ServerFactory = Callable[..., AbstractAsyncContextManager[RunningServer]]


@asynccontextmanager
async def mcp_session(
    url: str, token: str, *, mode: str = "auto"
) -> AsyncIterator[tuple[Client, httpx2.AsyncClient]]:
    """An SDK client whose every request carries `Bearer token`.

    mode="auto" negotiates the modern protocol (2026-07-28: no session id, each
    request stands alone); mode="legacy" uses the initialize handshake and a
    stateful session (Mcp-Session-Id). Change http.headers["Authorization"] to
    swap the token mid-session.
    """
    http = httpx2.AsyncClient(
        headers={"Authorization": f"Bearer {token}"}, timeout=httpx2.Timeout(30.0)
    )
    async with http, Client(streamable_http_client(url, http_client=http), mode=mode) as client:
        yield client, http


def rpc_result(response: httpx2.Response) -> dict[str, Any]:
    """The JSON-RPC message in a response (plain JSON or a single SSE event)."""
    if response.headers.get("content-type", "").startswith("text/event-stream"):
        for line in response.text.splitlines():
            if line.startswith("data:"):
                message: dict[str, Any] = json.loads(line[len("data:") :])
                if "id" in message:
                    return message
        raise AssertionError(f"no JSON-RPC response in SSE body: {response.text[:200]}")
    body: dict[str, Any] = response.json()
    return body


MODERN_VERSION = "2026-07-28"


def modern_request(
    method: str,
    params: dict[str, Any] | None = None,
    *,
    request_id: int = 1,
    name: str | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    """A raw 2026-07-28 request (no session): the JSON body and its MCP headers.

    Modern requests carry their protocol version and client capabilities in
    params._meta, and the method (and tool name) as headers.
    """
    body_params = dict(params or {})
    body_params["_meta"] = {
        "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    headers = {"Mcp-Protocol-Version": MODERN_VERSION, "Mcp-Method": method}
    if name is not None:
        headers["Mcp-Name"] = name
    body = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": body_params}
    return body, headers
