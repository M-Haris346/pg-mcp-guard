"""Constants and helpers shared by the executor and MCP tests (not fixtures)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from app.auth import Principal
from app.executor import Executor
from app.validator import Verdict
from scripts.seed import ACME, ALICE, BOB, GLOBEX, MALLORY

ALICE_AT_ACME = Principal(user_id=ALICE, tenant_id=ACME)
BOB_AT_GLOBEX = Principal(user_id=BOB, tenant_id=GLOBEX)
MALLORY_AT_ACME = Principal(user_id=MALLORY, tenant_id=ACME)  # not a member

# Port 1 on loopback: nothing listens, connections fail fast.
UNREACHABLE_URL = "postgresql://nobody:nothing@127.0.0.1:1/none?connect_timeout=1"

ExecutorFactory = Callable[..., Awaitable[Executor]]


def allow_all(sql: str) -> Verdict:
    """Validator OFF: shows what the database and executor do on their own."""
    return Verdict(allowed=True)


def last_audit(migrator: Any, marker: str) -> tuple[Any, ...] | None:
    """The newest audit row whose sql_text contains marker (read as migrator)."""
    row: tuple[Any, ...] | None = migrator.execute(
        "SELECT user_id, tenant_id, tool, sql_text, verdict, reason, row_count, truncated,"
        " duration_ms FROM audit.tool_calls WHERE strpos(sql_text, %s) > 0"
        " ORDER BY id DESC LIMIT 1",
        (marker,),
    ).fetchone()
    return row


def last_audit_for_tool(migrator: Any, tool: str) -> tuple[Any, ...] | None:
    """The newest audit row for a tool (for calls without sql_text)."""
    row: tuple[Any, ...] | None = migrator.execute(
        "SELECT user_id, tenant_id, tool, sql_text, verdict, reason, row_count, truncated,"
        " duration_ms FROM audit.tool_calls WHERE tool = %s ORDER BY id DESC LIMIT 1",
        (tool,),
    ).fetchone()
    return row
