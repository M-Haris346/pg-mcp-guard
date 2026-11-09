# Threat model

What pg-mcp-guard protects, from whom, where the trust boundaries are, which control stops each
attack, and which test proves it. Residual risks are at the end. Design rationale is in the
[ADRs](decisions/README.md).

## Assets

| Asset | Where it lives |
|---|---|
| Tenant data (orders, customers, products, …) | schema `shop`, protected by row-level security |
| Sensitive columns (`customers.email`, `customers.phone`) | schema `shop`, never granted to the runtime role |
| Identity: which user, which tenant | the principal token (JWT), then a signed context in the database (`mcpguard.ctx`) |
| The context key, JWT secret, database passwords | `.env` on the server host; the key also in `private.context_key` |
| Database availability | Postgres: CPU, memory, disk, connections, locks |
| The audit trail | `audit.tool_calls`, append-only for `mcp_auditor` |

## Actors

| Actor | Can do | Trusted? |
|---|---|---|
| **The model** | Write any SQL text and any tool arguments | No |
| **Prompt-injected data** | Text in rows the model reads, which may try to instruct the model | No |
| **A malicious HTTP caller** | Send any request, with or without a token, reuse or guess session ids, send oversized bodies or foreign Host / Origin headers | No |
| **The operator** | Runs the server, holds `.env` | stdio: fully trusted (can mint any identity). HTTP: trusted to run the server; callers do not need to trust each other |

## Trust boundaries

```
model ──(SQL text)──▶ MCP client ──(stdio | HTTP + bearer token)──▶ server ──(mcp_reader)──▶ Postgres
                                                                       └──(mcp_auditor)──▶ audit
```

- **stdio** (ADR [0005](decisions/0005-mcp-server.md)): one principal per process, verified at
  startup. The JWT protects against the *model* choosing identity, not against the operator, who
  holds the secret.
- **HTTP** (ADR [0006](decisions/0006-http-transport.md)): many principals per process. The bearer
  token of **every request** is the identity. Only the server holds the secrets.
- **Server to Postgres:** the server is not trusted to hold the line. The database enforces every
  data property on its own, and the database tests run **with the validator disabled**.

## Attacks, controls, proof

Layers: **DB** = role, grants, RLS, role limits, revoked functions. **V** = the validator.
**E** = the executor. **T** = transport and auth.

| Attack | Stopped by | Proof |
|---|---|---|
| Read another tenant's rows | **DB**: `FORCE` RLS keyed to the signed context; **T**: identity never from tool args | [tests/db/test_rls.py](../tests/db/test_rls.py), [tests/http/test_isolation.py](../tests/http/test_isolation.py) |
| Forge, tamper with or replay the context (`ctx.set_context` / `SET` / `set_config`) | **DB**: HMAC, expiry, ≤ 300 s lifetime and membership checked in the helper; `set_config` revoked; **V**: function allowlist | [tests/db/test_rls.py](../tests/db/test_rls.py), [tests/db/test_set_config.py](../tests/db/test_set_config.py) |
| Read `email` / `phone`, or a whole row (`c::text`) | **DB**: column grants (the validator allows these on purpose) | [tests/db/test_grants.py](../tests/db/test_grants.py), [tests/executor/test_errors.py](../tests/executor/test_errors.py) |
| Read catalogs, `pg_stat_activity`, `users`, the key, the audit table | **DB**: no grants, revoked functions; **V**: relation allowlist | [tests/db/test_grants.py](../tests/db/test_grants.py), [relations.toml](../tests/validator/corpus/relations.toml) |
| Write anything (INSERT … DROP, large objects) | **DB**: owns nothing, SELECT-only, read-only transaction (two layers); **V**: single `SelectStmt` | [tests/db/test_grants.py](../tests/db/test_grants.py), [statements.toml](../tests/validator/corpus/statements.toml) |
| `COMMIT; DROP …` (the Datadog case) | **E**: extended protocol / `DECLARE … CURSOR FOR` refuse it; **DB**: read-only and no ownership; **V**: one statement | [tests/db/test_grants.py](../tests/db/test_grants.py), [tests/executor/test_transaction.py](../tests/executor/test_transaction.py), [multi_statement.toml](../tests/validator/corpus/multi_statement.toml) |
| Hide a function in ORDER BY, LATERAL, VALUES, a CTE, … | **V**: whole-tree walk, deny by default | [hidden_functions.toml](../tests/validator/corpus/hidden_functions.toml) |
| Quoting, comment and `U&""` tricks | **V**: Postgres's own parser (pglast, same 18.6 grammar) | [identifiers.toml](../tests/validator/corpus/identifiers.toml), [quoting_comments.toml](../tests/validator/corpus/quoting_comments.toml) |
| Lift one's own limits (`statement_timeout`, `lock_timeout`, `work_mem`, `idle_in_transaction_session_timeout`) | **DB**: `set_config` revoked from the reader; startup refuses if it isn't; **E**: SET LOCAL limits and deadline; **V**: `SET` / `set_config` rejected | [tests/db/test_set_config.py](../tests/db/test_set_config.py), [tests/executor/test_timeout_gucs.py](../tests/executor/test_timeout_gucs.py) |
| Long or CPU-heavy query | **DB**: `statement_timeout`; **E**: deadline, server-side cancel, hard backstop | [tests/db/test_limits.py](../tests/db/test_limits.py), [tests/executor/test_deadline.py](../tests/executor/test_deadline.py) |
| Huge spilling sort | **DB**: `temp_file_limit` (superuser-only setting) | [tests/db/test_limits.py](../tests/db/test_limits.py), [tests/executor/test_errors.py](../tests/executor/test_errors.py) |
| Lock waits | **DB**: `lock_timeout`; **E**: deadline | [tests/db/test_limits.py](../tests/db/test_limits.py), [tests/executor/test_timeout_gucs.py](../tests/executor/test_timeout_gucs.py) |
| Unbounded results or huge cells | **E**: `max_rows + 1` via the cursor, cell and response byte caps | [tests/executor/test_bounds.py](../tests/executor/test_bounds.py) |
| Exhaust connections | **DB**: `CONNECTION LIMIT`; **E**: small pools, acquire timeout | [tests/db/test_limits.py](../tests/db/test_limits.py) |
| Cancel or terminate another caller's query | **DB**: `pg_cancel_backend` / `pg_terminate_backend` revoked | [tests/db/test_grants.py](../tests/db/test_grants.py) |
| Leave state (advisory locks) for the next caller | **E**: `DISCARD ALL` on pool return; a timed-out or cancelled connection is closed, never reused | [tests/executor/test_reset.py](../tests/executor/test_reset.py), [tests/executor/test_cancel.py](../tests/executor/test_cancel.py) |
| A late cancel hitting the next caller | **E**: the query task finishes before release; a connection that saw a cancel is closed | [tests/executor/test_deadline.py](../tests/executor/test_deadline.py) |
| Crash the server with deep nesting | **V**: parse in a 64 MB-stack thread, depth and length limits | [tests/validator/test_validator.py](../tests/validator/test_validator.py) |
| Pass identity as a tool argument (`tenant_id`, …) | **T**: strict schemas (`additionalProperties: false`), rejected and audited | [tests/mcp/test_tools.py](../tests/mcp/test_tools.py) |
| No, bad, expired or `alg=none` token; a non-member | **T**: HS256 only, required claims, ≤ 12 h lifetime; generic 401, audited | [tests/test_auth.py](../tests/test_auth.py), [tests/http/test_auth.py](../tests/http/test_auth.py), [tests/mcp/test_stdio.py](../tests/mcp/test_stdio.py) |
| Reuse a session id with another token | **T**: SDK session-owner check (404); **the per-request token decides even with that check off** | [tests/http/test_isolation.py](../tests/http/test_isolation.py) |
| DNS rebinding (foreign Host / Origin) | **T**: always-on allowlists (421 / 403) | [tests/http/test_transport.py](../tests/http/test_transport.py) |
| Oversized request bodies, session flooding | **T**: 256 KiB body limit (413, checked after auth); session cap (503) | [tests/http/test_transport.py](../tests/http/test_transport.py) |
| Data that tries to instruct the model | **T**: results labelled and fenced as untrusted; `<` escaped so neither data nor aliases can close the fence | [tests/mcp/test_tools.py](../tests/mcp/test_tools.py) |
| Leak internals in errors or logs | **E**: mapped, scrubbed reasons; **T**: no token or `Authorization` header in logs (checked at DEBUG) | [tests/executor/test_errors.py](../tests/executor/test_errors.py), [tests/http/test_process.py](../tests/http/test_process.py) |
| Act without leaving an audit trail | **E**: every call audited; no row, no result (fail closed); cancellations audited | [tests/executor/test_audit.py](../tests/executor/test_audit.py), [tests/db/test_audit.py](../tests/db/test_audit.py) |

## Finding from our own gap check (Phase 6)

We asked whether SQL that got past the validator could lift its own limits with
`set_config(name, value, false)`. It could. Measured before the fix, validator off, against the real
executor (`statement_timeout` 3 s, deadline 4 s, 50-row fetch batches):

| Attempt | Result | Bounded by |
|---|---|---|
| A: `statement_timeout` → 0, sleep in the same FETCH | `query_timeout` at 3.03 s | the server timer, armed before `set_config` ran |
| B: `statement_timeout` → 0, slow work in the 2nd FETCH | `query_timeout` at 4.03 s, connection replaced | the executor deadline only |
| C': `lock_timeout` and `statement_timeout` → 0, runtime lock wait | `query_timeout` at 4.03 s, connection replaced | the executor deadline only |
| D: `work_mem` → 2 GB | accepted | time only; **memory unbounded** |
| E: `idle_in_transaction_session_timeout` → 0, idle 12 s | session alive (control: killed at 10 s) | **nothing at the DB layer** if the server process stalls mid-transaction |

The fix (ADR [0002](decisions/0002-signed-rls-context.md)):
- `set_config` is revoked from PUBLIC and granted back only to the owner of `ctx.set_context`, which
  sets the context and nothing else;
- the executor sets its limits with `SET LOCAL` from validated integers;
- the server refuses to start if the reader can still call `set_config`.

All five attempts now fail at once with `function_not_allowed: set_config`, and are audited. With
the revoke undone, 22 tests fail and the server refuses to start.

## Residual risks

- **Exfiltration by the client.** The server bounds *what* a principal can read, not what the MCP
  client does with it. A client that also has web-fetch or e-mail tools could send rows the
  principal may legitimately read elsewhere.
- **HS256 shared secret.** Anyone who can verify a token can also mint one. Fine for a local demo;
  swap in an asymmetric or OIDC verifier for real use. In stdio mode the operator can be anyone.
- **No TLS.** Over plain HTTP, bearer tokens are readable on the network. Non-loopback binds need
  explicit opt-in; terminate TLS in a reverse proxy.
- **Pids are visible in `pg_locks`.** The reader can list backend pids. With cancel and terminate
  revoked, a pid alone gives no capability.
- **Revocation window.** A token stays valid until `exp` (at most 12 h, usually much shorter). A
  removed membership gives zero rows at once (RLS checks every query) and a 401 on HTTP within the
  30 s membership cache.
- **Session advisory locks** can still be taken by model SQL with the validator off. `DISCARD ALL`
  releases them before the connection is reused. Within one call they are bounded by the deadline.
- **A single huge cell** reaches the client whole before the cell cap cuts it. It is bounded by
  `statement_timeout`, the deadline and Postgres's 1 GB field limit.
- **No audit row if the process dies mid-call.** The row is written after execution.
- **Pinned SDK internals.** We rely on the `mcp` SDK's:
  - per-message contextvar snapshot;
  - session-owner check;
  - `ServerMiddleware` hook;
  - async socket registration (used by the cancel backstop).

  All are pinned (`mcp==2.3.0`, `psycopg` via `uv.lock`) and covered by tests that fail if they
  change.
- **Unknown tool names** are answered by the SDK and not audited.
