"""validate -> execute bounded -> audit (CLAUDE.md rules 5-7, 9; ADR 0004).

run_query(principal, sql):
1. Validate off the event loop (asyncio.to_thread). Rejected SQL never touches
   a reader connection.
2. On a pooled mcp_reader connection: BEGIN READ ONLY, signed context and
   limits as transaction-local settings (bind parameters), a server-side cursor
   (DECLARE is always sent with the extended protocol, which refuses more than
   one statement), and FETCH at most max_rows + 1 rows, in batches, with cell
   and response byte caps. Always ROLLBACK.
3. A client-side deadline covers the whole query. Past it: server-side cancel;
   past deadline + grace: the query task is cancelled and the connection
   closed. A connection that saw a cancel is never reused, because a late
   cancel would hit whatever that backend runs next. External cancellation
   (the caller cancels run_query) is handled the same way.
4. Write the audit row as mcp_auditor, shielded from cancellation. If that
   fails, return no result.
"""

from __future__ import annotations

import asyncio
import json
import math
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from datetime import time as dt_time
from decimal import Decimal
from typing import Any
from uuid import UUID

import psycopg
from psycopg import errors
from psycopg_pool import PoolTimeout

from app.audit import AuditRecord, Verdict, write_audit
from app.auth import Principal
from app.config import Limits
from app.db import Conn, Pools, read_only_transaction
from app.log import get_logger
from app.validator import DEFAULT_POLICY
from app.validator import Verdict as ValidatorVerdict
from app.validator import validate as default_validate

log = get_logger("executor")

JSONValue = None | bool | int | float | str | list["JSONValue"]
Validator = Callable[[str], ValidatorVerdict]

# Name of the task that runs the database work; tests use it to check that the
# task has finished before the connection goes back to the pool.
QUERY_TASK_NAME = "mcp-query"
AUDIT_TASK_NAME = "mcp-audit"
CURSOR_NAME = "mcp_query"

# A query_error detail mentioning any of these is replaced by the bare code.
_INTERNAL_MARKERS = ("mcp_", "mcpguard", "private", "ext.", "audit", "context_key")
_MAX_ERROR_DETAIL = 200
# After the query task is cancelled (hard backstop), how long to wait for it
# before closing the connection underneath it.
_TASK_CANCEL_WAIT_S = 1.0
# Margin over the auditor role's statement_timeout (2 s) when bounding the
# audit write.
_AUDIT_STATEMENT_BOUND_S = 3.0


@dataclass(frozen=True)
class QueryResult:
    columns: list[str]
    rows: list[list[JSONValue]]
    row_count: int
    truncated: bool
    truncated_reason: str | None  # None | "max_rows" | "cell_bytes" | "response_bytes"

    def to_dict(self) -> dict[str, Any]:
        return {
            "columns": self.columns,
            "rows": self.rows,
            "row_count": self.row_count,
            "truncated": self.truncated,
            "truncated_reason": self.truncated_reason,
        }


@dataclass(frozen=True)
class ToolError:
    reason: str  # model-readable, e.g. "function_not_allowed: pg_sleep"

    def to_dict(self) -> dict[str, Any]:
        return {"error": self.reason}


class _Timeout(Exception):
    """Raised when the client-side deadline (or its backstop) ended the query."""


@dataclass
class Executor:
    pools: Pools
    context_key: bytes
    limits: Limits = field(default_factory=Limits)
    validator: Validator = default_validate

    async def run_query(self, principal: Principal, sql: str) -> QueryResult | ToolError:
        """Validate, execute, audit. Never raises, except CancelledError when the
        caller cancels (MCP notifications/cancelled, HTTP disconnect); even then
        the call is audited first, with reason "cancelled"."""
        started = time.monotonic()
        outcome: QueryResult | ToolError
        verdict: Verdict
        cancelled: asyncio.CancelledError | None = None

        try:
            outcome, verdict = await self._check_and_execute(principal, sql)
        except asyncio.CancelledError as exc:
            cancelled = exc
            outcome, verdict = ToolError("cancelled"), "error"

        record = AuditRecord(
            principal=principal,
            tool="run_query",
            sql_text=audit_sql_text(sql),
            verdict=verdict,
            reason=outcome.reason if isinstance(outcome, ToolError) else outcome.truncated_reason,
            row_count=outcome.row_count if isinstance(outcome, QueryResult) else None,
            truncated=outcome.truncated if isinstance(outcome, QueryResult) else None,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        audited, cancelled_during_audit = await self._audit(record)
        cancelled = cancelled or cancelled_during_audit
        if cancelled is not None:
            raise cancelled
        if not audited:
            # Fail closed (rule 9): an unaudited call returns nothing.
            return ToolError("audit_unavailable")
        return outcome

    async def _check_and_execute(
        self, principal: Principal, sql: str
    ) -> tuple[QueryResult | ToolError, Verdict]:
        try:
            check = await asyncio.to_thread(self.validator, sql)
        except Exception as exc:  # a validator bug: fail closed
            log.error("validator_failed", error=type(exc).__name__)
            check = ValidatorVerdict(allowed=False, reason="internal_error")

        if not check.allowed:
            return ToolError(check.reason or "rejected"), "rejected"
        outcome = await self._execute(principal, sql)
        return outcome, ("allowed" if isinstance(outcome, QueryResult) else "error")

    async def _audit(self, record: AuditRecord) -> tuple[bool, asyncio.CancelledError | None]:
        """Write the audit row even if the caller cancels us meanwhile.

        The write runs in its own task behind asyncio.shield, so a cancellation
        of run_query does not abort it. It is bounded by the pool acquire
        timeout plus a margin over the auditor role's 2 s statement_timeout.
        Returns (written, the CancelledError that arrived meanwhile, if any).
        """
        loop = asyncio.get_running_loop()
        give_up = loop.time() + self.limits.pool_acquire_timeout_s + _AUDIT_STATEMENT_BOUND_S
        task = asyncio.create_task(
            write_audit(
                self.pools.auditor, record, acquire_timeout_s=self.limits.pool_acquire_timeout_s
            ),
            name=AUDIT_TASK_NAME,
        )
        interrupted: asyncio.CancelledError | None = None
        while not task.done():
            remaining = give_up - loop.time()
            if remaining <= 0:
                task.cancel()
                break
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=remaining)
            except asyncio.CancelledError as exc:
                interrupted = exc  # remember it, keep waiting for the write
            except Exception:  # noqa: S112 - the task's own error is handled below
                continue

        if not task.done() or task.cancelled():
            log.error("audit_write_timed_out")
            return False, interrupted
        if (error := task.exception()) is not None:
            log.error("audit_write_failed", error=type(error).__name__)
            return False, interrupted
        return True, interrupted

    # --- execution ----------------------------------------------------------

    async def _execute(self, principal: Principal, sql: str) -> QueryResult | ToolError:
        try:
            async with self.pools.reader.connection(
                timeout=self.limits.pool_acquire_timeout_s
            ) as conn:
                return await self._run_with_deadline(conn, principal, sql)
        except _Timeout:
            return ToolError("query_timeout")
        except PoolTimeout:
            return ToolError("unavailable")
        except psycopg.Error as exc:
            return ToolError(map_db_error(exc))

    async def _run_with_deadline(
        self, conn: Conn, principal: Principal, sql: str
    ) -> QueryResult | ToolError:
        """Run the query in a child task and police the deadline from here.

        The task is always finished (or the connection closed under it) before
        this returns, so nothing is still running when the connection goes back
        to the pool. If the deadline fired at all, the connection is closed,
        never reused: a cancel request that arrives late would hit whatever the
        backend runs next (the next principal's query, or DISCARD ALL).
        """
        work = asyncio.create_task(self._query(conn, principal, sql), name=QUERY_TASK_NAME)
        fired = False
        try:
            try:
                done, _ = await asyncio.wait({work}, timeout=self.limits.deadline_ms / 1000)
                if not done:
                    fired = True
                    await self._stop(conn, work)
                    raise _Timeout
            except asyncio.CancelledError:
                # External cancellation (or a cancel during _stop): treat it
                # like a fired deadline. Backstop order, synchronously, so a
                # second cancellation cannot interrupt it: unregister the
                # socket and close the connection, then cancel the query task.
                fired = True
                _sever(conn)
                work.cancel()
                await asyncio.wait({work}, timeout=_TASK_CANCEL_WAIT_S)
                if work.done():
                    _consume(work)
                raise
            exc = work.exception()
            if exc is None:
                return work.result()
            if isinstance(exc, psycopg.Error):
                return ToolError(map_db_error(exc))
            # Anything else (e.g. psycopg refusing to send a NUL character) is
            # not the model's business: log the class, return a generic error.
            log.error("query_failed", error=type(exc).__name__)
            return ToolError("internal_error")
        finally:
            if not work.done():  # e.g. we were cancelled ourselves
                work.cancel()
                await asyncio.wait({work}, timeout=_TASK_CANCEL_WAIT_S)
            if fired and not conn.closed:
                await conn.close()  # the pool discards closed connections

    async def _stop(self, conn: Conn, work: asyncio.Task[QueryResult]) -> None:
        """Deadline passed: cancel on the server, then the hard backstop."""
        loop = asyncio.get_running_loop()
        grace_end = loop.time() + self.limits.cancel_grace_ms / 1000
        try:
            await conn.cancel_safe(timeout=self.limits.cancel_grace_ms / 1000)
        except Exception as exc:
            log.warning("cancel_failed", error=type(exc).__name__)
        await asyncio.wait({work}, timeout=max(0.0, grace_end - loop.time()))
        if work.done():
            _consume(work)
            return

        # Backstop: the server did not stop in time. Sever the connection
        # first, then cancel the task. In this order psycopg sees a closed
        # connection and re-raises at once, instead of its own built-in
        # path (cancel again, then wait a fixed 5 s).
        log.warning("query_cancel_backstop")
        _sever(conn)
        work.cancel()
        await asyncio.wait({work}, timeout=_TASK_CANCEL_WAIT_S)
        if work.done():
            _consume(work)
        else:
            log.error("query_task_stuck_after_backstop")

    async def _query(self, conn: Conn, principal: Principal, sql: str) -> QueryResult:
        async with read_only_transaction(conn, principal, self.context_key, self.limits):
            async with conn.cursor(name=CURSOR_NAME) as cursor:
                # Validated above (or deliberately not, in validator-off tests).
                # DECLARE is always sent with the extended protocol.
                await cursor.execute(sql)
                columns = [col.name for col in cursor.description or ()]
                return await self._fetch(cursor, columns)

    async def _fetch(
        self, cursor: psycopg.AsyncServerCursor[tuple[Any, ...]], columns: list[str]
    ) -> QueryResult:
        limits = self.limits
        rows: list[list[JSONValue]] = []
        total_bytes = _json_bytes(columns)
        row_limit_hit: str | None = None
        cell_cut = False
        fetched = 0

        # Never more than max_rows + 1 rows leave the server.
        while fetched < limits.max_rows + 1 and row_limit_hit is None:
            batch = await cursor.fetchmany(
                min(limits.fetch_batch_rows, limits.max_rows + 1 - fetched)
            )
            if not batch:
                break
            fetched += len(batch)
            for raw in batch:
                if len(rows) == limits.max_rows:
                    row_limit_hit = "max_rows"
                    break
                row, row_bytes, cut = serialize_row(raw, limits.max_cell_bytes)
                if total_bytes + row_bytes > limits.max_response_bytes:
                    row_limit_hit = "response_bytes"
                    break
                rows.append(row)
                total_bytes += row_bytes
                cell_cut = cell_cut or cut

        reason = row_limit_hit or ("cell_bytes" if cell_cut else None)
        return QueryResult(
            columns=columns,
            rows=rows,
            row_count=len(rows),
            truncated=reason is not None,
            truncated_reason=reason,
        )


def audit_sql_text(sql: str) -> str:
    """The SQL as stored in the audit log: bounded, and storable.

    Postgres text cannot hold NUL, and a failed audit insert would turn every
    such call into audit_unavailable; NUL is stored visibly escaped instead.
    """
    return sql[: DEFAULT_POLICY.max_sql_chars].replace("\x00", "\\x00")


def _sever(conn: Conn) -> None:
    """Close a connection's socket while a query task may be waiting on it.

    psycopg's async wait registers the socket with the event loop
    (loop.add_reader / add_writer on pgconn.socket). Closing the socket while
    it is still registered breaks the loop's select() for every task
    (WinError 10038 on Windows), so unregister it first, then close.
    The waiting task wakes on its next poll interval or its cancellation and
    finds the connection closed. tests/executor/test_deadline.py covers this.
    """
    loop = asyncio.get_running_loop()
    try:
        fd = conn.pgconn.socket
    except psycopg.OperationalError:  # already closed
        return
    loop.remove_reader(fd)
    loop.remove_writer(fd)
    conn.pgconn.finish()


def _consume(task: asyncio.Task[QueryResult]) -> None:
    """Retrieve a finished task's exception so asyncio does not log it as unhandled."""
    if not task.cancelled():
        task.exception()


# --- values ---------------------------------------------------------------


def to_json_value(value: object) -> JSONValue:
    """Convert a value psycopg returned into strict-JSON-safe data."""
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        if math.isnan(value):
            return "NaN"
        if math.isinf(value):
            return "Infinity" if value > 0 else "-Infinity"
        return value
    if isinstance(value, Decimal):
        if value.is_nan():
            return "NaN"
        if value.is_infinite():
            return "Infinity" if value > 0 else "-Infinity"
        return str(value)  # a string keeps full precision
    if isinstance(value, datetime | date | dt_time):
        return value.isoformat()
    if isinstance(value, timedelta | UUID):
        return str(value)
    if isinstance(value, list | tuple):
        return [to_json_value(v) for v in value]
    if isinstance(value, bytes | bytearray | memoryview):
        return bytes(value).hex()
    return str(value)


def _json_bytes(value: object) -> int:
    return len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8"))


def serialize_row(raw: Sequence[object], max_cell_bytes: int) -> tuple[list[JSONValue], int, bool]:
    """Return (cells, bytes, any_cell_cut). Oversized cells become cut strings."""
    cells: list[JSONValue] = []
    total = 0
    cut = False
    for item in raw:
        value = to_json_value(item)
        size = _json_bytes(value)
        if size > max_cell_bytes:
            text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
            # Cut on a UTF-8 character boundary.
            value = text.encode("utf-8")[:max_cell_bytes].decode("utf-8", errors="ignore")
            size = _json_bytes(value)
            cut = True
        cells.append(value)
        total += size
    return cells, total, cut


# --- errors ---------------------------------------------------------------


def map_db_error(exc: BaseException) -> str:
    """Map a database error to a model-readable reason. Never leaks internals."""
    if isinstance(exc, errors.InsufficientPrivilege):
        # With the validator on, column grants are the only source of 42501.
        return "column_not_allowed"
    if isinstance(exc, errors.QueryCanceled):
        return "query_timeout"
    if isinstance(exc, errors.LockNotAvailable):
        return "lock_timeout"
    if isinstance(exc, errors.ReadOnlySqlTransaction):
        return "read_only"

    sqlstate = getattr(exc, "sqlstate", None)
    if sqlstate is None or sqlstate.startswith("08"):
        if isinstance(exc, psycopg.OperationalError | psycopg.InterfaceError):
            return "unavailable"
    elif sqlstate.startswith("53"):  # insufficient resources, incl. temp_file_limit
        return "resource_limit"
    elif sqlstate == "42601" and "cannot insert multiple commands" in str(exc):
        return "multiple_statements"
    elif sqlstate[:2] in {"22", "42"}:
        # Data exceptions and syntax / undefined-object errors: the message
        # helps the model fix its query. Any value it quotes can only come
        # from the query itself or from rows RLS lets this principal see.
        diag = getattr(exc, "diag", None)
        message = getattr(diag, "message_primary", None) or ""
        return _query_error(message)

    log.warning("unmapped_db_error", error=type(exc).__name__, sqlstate=sqlstate)
    return "internal_error"


def _query_error(message: str) -> str:
    detail = "".join(ch for ch in message if ch.isprintable())[:_MAX_ERROR_DETAIL]
    lowered = detail.lower()
    if not detail or any(marker in lowered for marker in _INTERNAL_MARKERS):
        return "query_error"
    return f"query_error: {detail}"
