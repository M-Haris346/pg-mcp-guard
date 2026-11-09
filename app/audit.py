"""Audit log writes (rule 9), as mcp_auditor: INSERT only.

Records what was asked and what happened. Never result data, tokens or secrets.
The executor fails closed: if write_audit raises, the caller gets no result.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.auth import Principal
from app.db import Pool

Verdict = Literal["allowed", "rejected", "error"]

INSERT_SQL = (
    "INSERT INTO audit.tool_calls"
    " (user_id, tenant_id, tool, sql_text, verdict, reason, row_count, truncated, duration_ms)"
    " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
)


@dataclass(frozen=True)
class AuditRecord:
    principal: Principal
    tool: str
    sql_text: str | None
    verdict: Verdict
    reason: str | None
    row_count: int | None
    truncated: bool | None
    duration_ms: int


async def write_audit(pool: Pool, record: AuditRecord, *, acquire_timeout_s: float) -> None:
    async with pool.connection(timeout=acquire_timeout_s) as conn:
        await conn.execute(
            INSERT_SQL,
            (
                record.principal.user_id,
                record.principal.tenant_id,
                record.tool,
                record.sql_text,
                record.verdict,
                record.reason,
                record.row_count,
                record.truncated,
                record.duration_ms,
            ),
        )
