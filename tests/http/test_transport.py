"""DNS-rebinding protection (Host / Origin), request body limit, session cap."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx2
import pytest

from tests.http_support import ACCEPT, ServerFactory, mint, modern_request, rpc_result
from tests.support import ALICE_AT_ACME

LIST_TOOLS, MODERN_HEADERS = modern_request("tools/list")


def _headers(**extra: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {mint(ALICE_AT_ACME)}",
        "Accept": ACCEPT,
        "Content-Type": "application/json",
        **MODERN_HEADERS,
        **extra,
    }


@pytest.mark.parametrize(
    ("extra", "status"),
    [
        ({"Host": "evil.example:8765"}, 421),
        ({"Host": "127.0.0.1"}, 421),  # no port: does not match "127.0.0.1:*"
        ({"Origin": "http://evil.example"}, 403),
        ({"Origin": "http://evil.example:8765"}, 403),
        ({}, 200),  # no Origin (a non-browser client)
    ],
    ids=["foreign_host", "host_without_port", "foreign_origin", "foreign_origin_port", "no_origin"],
)
async def test_host_and_origin_checks(
    http_server: ServerFactory, extra: dict[str, str], status: int
) -> None:
    async with http_server() as srv, httpx2.AsyncClient() as http:
        response = await http.post(srv.url, json=LIST_TOOLS, headers=_headers(**extra))
    assert response.status_code == status


async def test_own_loopback_origin_is_allowed(http_server: ServerFactory) -> None:
    async with http_server() as srv, httpx2.AsyncClient() as http:
        response = await http.post(srv.url, json=LIST_TOOLS, headers=_headers(Origin=srv.origin))
    assert response.status_code == 200
    assert "tools" in rpc_result(response)["result"]


def _call_with_padding(size: int) -> bytes:
    """A valid tools/list request padded (inside a JSON string) to exactly `size` bytes."""
    body = dict(LIST_TOOLS)
    body["params"] = {**LIST_TOOLS["params"], "_pad": ""}
    empty = json.dumps(body, separators=(",", ":")).encode()
    body["params"]["_pad"] = "x" * (size - len(empty))
    padded = json.dumps(body, separators=(",", ":")).encode()
    assert len(padded) == size
    return padded


async def test_body_at_the_limit_is_accepted(http_server: ServerFactory) -> None:
    async with http_server(max_body_bytes=4096) as srv, httpx2.AsyncClient() as http:
        response = await http.post(srv.url, content=_call_with_padding(4096), headers=_headers())
    assert response.status_code == 200


async def test_oversized_body_gets_413(http_server: ServerFactory) -> None:
    async with http_server(max_body_bytes=4096) as srv, httpx2.AsyncClient() as http:
        response = await http.post(srv.url, content=_call_with_padding(4097), headers=_headers())
    assert response.status_code == 413
    assert response.text == "Request body too large"


async def test_oversized_streamed_body_without_length_gets_413(http_server: ServerFactory) -> None:
    async def chunks() -> AsyncIterator[bytes]:
        body = _call_with_padding(8192)
        for start in range(0, len(body), 1024):
            yield body[start : start + 1024]

    async with http_server(max_body_bytes=4096) as srv, httpx2.AsyncClient() as http:
        response = await http.post(srv.url, content=chunks(), headers=_headers())
    assert response.status_code == 413


async def test_unauthenticated_oversized_body_is_refused_before_it_is_read(
    http_server: ServerFactory,
) -> None:
    async with http_server(max_body_bytes=4096) as srv, httpx2.AsyncClient() as http:
        response = await http.post(
            srv.url, content=_call_with_padding(100_000), headers={"Accept": ACCEPT}
        )
    assert response.status_code == 401  # auth runs before the body is touched


async def test_session_cap(http_server: ServerFactory) -> None:
    initialize: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "cap-test", "version": "0"},
        },
    }
    legacy_headers = {
        "Authorization": f"Bearer {mint(ALICE_AT_ACME)}",
        "Accept": ACCEPT,
        "Content-Type": "application/json",
    }
    async with http_server(max_sessions=2) as srv, httpx2.AsyncClient() as http:
        statuses = [
            (await http.post(srv.url, json=initialize, headers=legacy_headers)).status_code
            for _ in range(3)
        ]
    assert statuses == [200, 200, 503]
