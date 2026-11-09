# ADR 0004: Executor: bounded read-only execution, deadline, fail-closed audit

Status: accepted (Phase 3)

## Context

The validator (ADR 0003) decides *whether* SQL may run. The executor decides *how*: which
connection, which transaction, which limits, how much data comes back, what the model sees when
something fails, and what is recorded. Each choice below is tested in `tests/executor/`, most of
them with the validator switched off.

## Decisions

**Validation off the event loop.** `validate()` is synchronous and starts a large-stack thread
(ADR 0003), so the executor calls it with `asyncio.to_thread`. Rejected SQL never reaches a reader
connection.

**One read-only transaction per query, always rolled back.**
- `BEGIN READ ONLY` is sent explicitly (psycopg `read_only=True`). The role's
  `default_transaction_read_only` is a second, independent layer, and a test turns it off to show
  the first one holds alone.
- Transaction-local settings are applied in one statement, with every value as a bind parameter:
  `set_config(name, value, true)` is exactly `SET LOCAL`, but `SET` cannot take parameters, and the
  context token must travel only as a parameter (rule 4). The settings are: `mcpguard.ctx` (signed
  token), `statement_timeout` (3 s, below the role's 5 s), `lock_timeout` (1 s),
  `search_path = shop`, and `client_connection_check_interval = 1s`. The last one makes a backend
  notice a closed client within a second.
- The transaction always ends in ROLLBACK. Postgres also undoes any GUC change made in a
  rolled-back transaction, including `set_config(..., false)`.

**Server-side cursor, at most `max_rows + 1` rows.**
- `DECLARE … CURSOR FOR <sql>` is always sent with the extended protocol (psycopg
  `force_extended=True`), which refuses a second statement. `DECLARE … FOR` must also be followed by
  a query, so `COMMIT; DROP …` fails as a syntax error.
- Rows are fetched in batches, never `fetchall`. A test proves laziness: row 6 divides by zero, and
  with `max_rows = 3` the query succeeds because row 6 is never computed.
- Cells over `max_cell_bytes` (UTF-8) are cut on a character boundary. Rows stop being added once
  `max_response_bytes` would be exceeded. The result reports `truncated` and `truncated_reason`
  (`max_rows` | `cell_bytes` | `response_bytes`).
- Values are converted to strict JSON. Decimal, UUID, date/time and interval become strings. NaN
  and ±Infinity (float8 and numeric) become the strings `"NaN"`, `"Infinity"` and `"-Infinity"`.

**Client-side deadline, server-side cancel, hard backstop.**
- The query runs in a child task. The executor waits on it with the deadline (4 s) and never uses
  `wait_for`, so it never cancels psycopg in the middle of a protocol exchange.
- When the deadline passes, the executor sends `cancel_safe()` and waits up to `cancel_grace_ms`
  (2 s).
- If the query still has not stopped, the backstop runs. It unregisters the socket from the event
  loop, closes the libpq connection, then cancels the task, in that order. Closing a socket that
  is still registered breaks the loop's `select()` for every task (seen as WinError 10038 during
  development). Cancelling first would send psycopg down its own path: cancel again, then wait a
  fixed 5 s.
- The deadline also covers the gaps between FETCHes. Each FETCH has its own `statement_timeout`,
  so a slow-row query (or one that set `statement_timeout = 0` partway through, validator off) is
  stopped only by the deadline.

**Cancel race.** A Postgres cancel request hits whatever the backend is running when it arrives.
- The query task is always finished before the connection is released (tested by wrapping
  `putconn`).
- If the deadline fired at all, the connection is closed, never returned. Even a late cancel can
  then only reach a backend that is about to exit, never the next principal's query or
  `DISCARD ALL`.
- Tested: after a timeout the next call gets a different backend pid, and with pool size 1, alice's
  timeout followed by bob's query returns bob's rows.

**External cancellation.** From Phase 4 on, the caller can cancel `run_query` (MCP
`notifications/cancelled`, an HTTP client disconnecting). The executor treats that exactly like a
fired deadline:
- it runs the backstop order synchronously (unregister the socket, close the libpq connection, then
  cancel the query task), so a second cancellation cannot interrupt it half-way;
- the connection is never returned to the pool;
- the call is still audited, with verdict `error` and reason `cancelled`, and only then is the
  `CancelledError` re-raised.

Every audit write runs in its own task behind `asyncio.shield`, bounded by the pool acquire timeout
plus a margin over the auditor role's 2 s `statement_timeout`. A cancellation that arrives during
the write is held until the write finishes, then re-raised.

Tested in `tests/executor/test_cancel.py` (pool size 1, validator off): a cancel during
`pg_sleep(5)`, a cancel during the audit write, and both in one call. Each test asserts:
- the `CancelledError` reaches the caller;
- the next call gets a different backend pid (after a cancel during the query);
- the audit row exists;
- no query or audit task is left pending, and no "Task was destroyed" report appears after
  `gc.collect()`.

Without this handling, the first test fails: the same backend is reused after the cancel.

**`DISCARD ALL` on pool return.** ROLLBACK already undoes session GUCs, but **session advisory
locks survive ROLLBACK**, and so would prepared statements or LISTEN registrations. `DISCARD ALL`
clears them. If the reset fails, psycopg_pool closes the connection. A test with the reset disabled
shows the advisory lock leaking to the next checkout.

**Error mapping.** Errors map to model-readable reasons and never to internals:

| Source | Reason |
|---|---|
| 42501 | `column_not_allowed` (with the validator on, only column grants raise it) |
| 57014 | `query_timeout` (server timeout, our cancel, or the deadline) |
| 55P03 | `lock_timeout` |
| class 53 (incl. `temp_file_limit`) | `resource_limit` |
| 25006 | `read_only` |
| "cannot insert multiple commands" | `multiple_statements` |
| other class 22 / 42 | `query_error: <primary message>` |
| connection / pool | `unavailable` |
| anything else | `internal_error`, logged to stderr with SQLSTATE and class only |

For `query_error`, the primary message helps the model fix its query. It is made printable, cut to
200 characters, and replaced by a bare `query_error` if it mentions `mcp_`, `mcpguard`, `private`,
`ext.`, `audit` or `context_key`. Any value it quotes comes from the model's own SQL or from rows
RLS already lets this principal see. A test sends every reject entry of the corpus to the database
with the validator off and asserts no reason leaks those names.

**Audit last, fail closed.** After execution the executor inserts one row as `mcp_auditor`. The row
records the principal, tool, SQL text (bounded, NUL escaped so Postgres can store it), verdict
(`allowed` / `rejected` / `error`), reason, row count, truncated flag and duration. It never records
rows, tokens or secrets. If the insert fails for any reason, the call returns
`audit_unavailable` and **no result**, for rejected calls too.

## Residual risks

1. **A single huge cell reaches the client whole.** Caps apply after a row arrives. A cell built on
   the server (e.g. `string_agg` over a large cross join) is bounded by `statement_timeout`, the
   deadline and Postgres's 1 GB field limit, not by `max_cell_bytes`. Capping it on the server would
   mean rewriting the model's SQL, which reintroduces a parser differential, so we don't.
2. **No audit row if the process dies mid-query.** The audit row is written after execution, so a
   crash (or kill) during a query leaves no trace of that call. We accept this for a read-only
   server: the call could not change data, and auditing first would need a second write
   (start + finish) per call. Recorded, not hidden.
3. **The backstop relies on psycopg internals.** It assumes psycopg's async wait registers
   `pgconn.socket` with the event loop (true for psycopg 3.3, pinned by `uv.lock`).
   `test_hard_backstop_when_the_server_ignores_the_cancel` fails if that changes.
4. **Cancellation outside the query is not specially handled.** A cancellation that arrives while
   waiting for a pool connection, during validation, or while the pool runs `DISCARD ALL` on return
   just propagates. The call is still audited as `cancelled`, but there is no backstop: at those
   points no model SQL is running on the connection. A cancel during `DISCARD ALL` goes through
   psycopg's own interrupt path, and psycopg_pool closes a connection it cannot reset. That path is
   not covered by a test.
5. **After the backstop the backend may run briefly on.** Closing the client does not kill the
   backend instantly. `client_connection_check_interval = 1s` makes it notice within about a
   second; `statement_timeout` bounds it regardless.
