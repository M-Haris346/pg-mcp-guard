"""Per-call token expiry and MCP cancellation, through a real client session."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest
from mcp import Client
from mcp.shared.exceptions import MCPError
from mcp_types import REQUEST_TIMEOUT, TextContent

from tests.mcp.conftest import ClientFactory
from tests.support import allow_all, last_audit, last_audit_for_tool

TOOL_CALLS = [
    ("list_tables", {}),
    ("describe_table", {"name": "orders"}),
    ("run_query", {"sql": "SELECT 1 /* t-expired */"}),
]


@pytest.mark.parametrize(("tool", "arguments"), TOOL_CALLS, ids=[t for t, _ in TOOL_CALLS])
async def test_valid_token_is_accepted_on_every_call(
    connect: ClientFactory, tool: str, arguments: dict[str, Any]
) -> None:
    async with connect(expires_in=60) as client:
        assert not (await client.call_tool(tool, arguments)).is_error


@pytest.mark.parametrize(("tool", "arguments"), TOOL_CALLS, ids=[t for t, _ in TOOL_CALLS])
async def test_token_that_expired_after_startup_is_refused_and_audited(
    connect: ClientFactory, migrator: Any, tool: str, arguments: dict[str, Any]
) -> None:
    # Verified at startup with an hour left; the clock has since moved past exp.
    async with connect(expires_in=3600, clock=lambda: time.time() + 7200) as client:
        result = await client.call_tool(tool, arguments)

    assert result.is_error
    block = result.content[0]
    assert isinstance(block, TextContent) and block.text == "principal_token_expired"
    row = last_audit_for_tool(migrator, tool)
    assert row is not None and row[4:6] == ("rejected", "principal_token_expired")


async def _pid(client: Client) -> int:
    result = await client.call_tool("run_query", {"sql": "SELECT pg_backend_pid()"})
    assert result.structured_content is not None
    pid = result.structured_content["rows"][0][0]
    assert isinstance(pid, int)
    return pid


async def _wait_for_audit(migrator: Any, marker: str, wait_s: float = 5.0) -> tuple[Any, ...]:
    """The server writes the row after it has processed the cancellation."""
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        row = last_audit(migrator, marker)
        if row is not None:
            return row
        await asyncio.sleep(0.05)
    raise AssertionError(f"no audit row for {marker}")


async def test_client_cancellation_reaches_the_query(connect: ClientFactory, migrator: Any) -> None:
    """The client gives up (timeout), sends notifications/cancelled; the server
    cancels the tool call, closes the connection and audits it as cancelled."""
    async with connect(validator=allow_all, reader_max=1) as client:
        before = await _pid(client)

        started = time.monotonic()
        with pytest.raises(MCPError) as raised:
            await client.call_tool(
                "run_query",
                {"sql": "SELECT pg_sleep(5) /* t-mcp-cancel */"},
                read_timeout_seconds=0.5,
            )
        assert raised.value.code == REQUEST_TIMEOUT
        row = await _wait_for_audit(migrator, "t-mcp-cancel")
        assert time.monotonic() - started < 3.0  # the query did not run its 5 s

        assert row[4:6] == ("error", "cancelled")
        assert await _pid(client) != before  # the connection was closed, not reused
