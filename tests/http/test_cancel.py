"""Cancellation over HTTP: notifications/cancelled and a client that just goes away.

Either way the query is cancelled, the call is audited as "cancelled", and the
reader connection is closed instead of reused (validator OFF so pg_sleep runs).
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx2
import pytest
from mcp.shared.exceptions import MCPError

from tests.http_support import ACCEPT, ServerFactory, mcp_session, mint, modern_request
from tests.support import ALICE_AT_ACME, allow_all, last_audit


async def _wait_for_audit(migrator: Any, marker: str, wait_s: float = 8.0) -> tuple[Any, ...]:
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        row = last_audit(migrator, marker)
        if row is not None:
            return row
        await asyncio.sleep(0.05)
    raise AssertionError(f"no audit row for {marker}")


async def _pid(url: str) -> int:
    async with mcp_session(url, mint(ALICE_AT_ACME)) as (client, _):
        result = await client.call_tool("run_query", {"sql": "SELECT pg_backend_pid()"})
    assert result.structured_content is not None
    pid = result.structured_content["rows"][0][0]
    assert isinstance(pid, int)
    return pid


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_client_cancellation_is_audited_and_the_connection_dropped(
    http_server: ServerFactory, migrator: Any, mode: str
) -> None:
    marker = f"t-http-cancel-{mode}"
    async with http_server(validator=allow_all, reader_max=1) as srv:
        before = await _pid(srv.url)
        async with mcp_session(srv.url, mint(ALICE_AT_ACME), mode=mode) as (client, _):
            started = time.monotonic()
            with pytest.raises(MCPError):
                await client.call_tool(
                    "run_query",
                    {"sql": f"SELECT pg_sleep(5) /* {marker} */"},
                    read_timeout_seconds=0.5,
                )
        row = await _wait_for_audit(migrator, marker)
        assert time.monotonic() - started < 4.0  # not the full 5 s sleep
        after = await _pid(srv.url)

    assert row[4:6] == ("error", "cancelled")
    assert after != before  # the connection that saw the cancel was not reused


async def test_client_disconnect_is_audited_and_the_connection_dropped(
    http_server: ServerFactory, migrator: Any
) -> None:
    """A raw client sends tools/call and then drops the connection."""
    marker = "t-http-disconnect"
    async with http_server(validator=allow_all, reader_max=1) as srv:
        before = await _pid(srv.url)
        call, mcp_headers = modern_request(
            "tools/call",
            {"name": "run_query", "arguments": {"sql": f"SELECT pg_sleep(5) /* {marker} */"}},
            request_id=7,
            name="run_query",
        )
        headers = {
            "Authorization": f"Bearer {mint(ALICE_AT_ACME)}",
            "Accept": ACCEPT,
            "Content-Type": "application/json",
            **mcp_headers,
        }
        http = httpx2.AsyncClient(timeout=httpx2.Timeout(0.5))
        started = time.monotonic()
        with pytest.raises(httpx2.TimeoutException):
            await http.post(srv.url, json=call, headers=headers)
        await http.aclose()  # the client is gone
        row = await _wait_for_audit(migrator, marker)
        assert time.monotonic() - started < 4.0
        after = await _pid(srv.url)

    assert row[4:6] == ("error", "cancelled")
    assert after != before
