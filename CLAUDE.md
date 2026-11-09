# CLAUDE.md — pg-mcp-guard

You are working on **pg-mcp-guard**, a portfolio project by Muhammad Haris.
It must be technically defensible in a senior-engineer code review and in an interview.
Haris must be able to explain every line. Prefer clear, boring code over clever code.

## 1. What this project is

An MCP (Model Context Protocol) server that lets an LLM agent run **read-only SQL** against a
PostgreSQL database, where safety is enforced by **the database first** and by a SQL validator
second — never by the prompt.

Core claim the repo must prove with automated tests:

> A model connected to this server can only read rows and columns its principal is allowed to read,
> cannot change any data or state, cannot exhaust the database, and every call is audited.
> This holds even if the model is prompt-injected by data it reads, and even if the SQL
> validator has a bug (tests run attacks with the validator disabled and the database must still hold).

Why this matters (cite in README): the archived reference Postgres MCP server ran model SQL inside a
`READ ONLY` transaction, and a multi-statement string (`COMMIT; DROP ...`) escaped it —
Datadog Security Labs, "MCP vulnerability case study: SQL injection in the PostgreSQL MCP server".
This repo exists to show the layered fix, with tests for each layer.

## 2. Non-negotiable security rules

1. **The model never sees or chooses identity.** Tools take SQL / a table name only — no tenant,
   user or role parameters. The principal comes from a verified JWT (stdio: at startup; HTTP: per request).
2. **Runtime DB role is `mcp_reader`:** `LOGIN NOSUPERUSER NOBYPASSRLS`, owns nothing, `SELECT` only on
   allowlisted tables, column-level grants for sensitive tables. Role-level settings:
   `default_transaction_read_only = on`, `statement_timeout`, `lock_timeout`,
   `idle_in_transaction_session_timeout`, `temp_file_limit`, `CONNECTION LIMIT`.
3. **Every RLS-protected table has `ENABLE` and `FORCE ROW LEVEL SECURITY`.**
4. **Identity reaches Postgres as a signed, short-lived context**, set with `set_config(..., true)`
   (transaction-local). Policies call a `SECURITY DEFINER` helper that verifies the HMAC (pgcrypto)
   with a key only `mcp_rls_helper` can read, and checks expiry. Reason: model-written SQL could call
   `set_config('mcpguard.ctx', ...)` itself; an unsigned GUC would let it impersonate another tenant.
   Invalid / missing / expired context ⇒ helper returns NULL ⇒ zero rows (fail closed).
5. **Every query runs in a `READ ONLY` transaction** with `SET LOCAL statement_timeout` and
   `SET LOCAL search_path` to the exposed schema only.
6. **Exactly one statement**, parsed with the real Postgres grammar (`pglast` / libpg_query).
   Top-level node must be `SelectStmt`. Reject: `INTO`, locking clauses (`FOR UPDATE/SHARE`),
   data-modifying CTEs, any relation not on the allowlist (incl. `pg_catalog`, `information_schema`),
   any function not on the **allowlist** (deny by default: `set_config`, `current_setting`, `pg_sleep`,
   `pg_read_file`, `dblink`, `lo_*` etc. are therefore rejected), casts to `reg*` types.
   Driver must also refuse multi-statement strings (prove with a validator-disabled test).
7. **Bounded results:** fetch at most `max_rows + 1` via a cursor (report `truncated`), cap cell and
   total response bytes. Never load an unbounded result into memory.
8. **Views exposed to the model must be `WITH (security_invoker = true)`** — a default view runs as its
   owner and would bypass RLS. A test asserts this for every exposed view.
9. **Audit every tool call, allowed or rejected**, via a separate role `mcp_auditor` that can only
   `INSERT` into `audit.tool_calls` (no SELECT/UPDATE/DELETE). `mcp_reader` cannot touch audit.
   If the audit write fails, the result is **not** returned (fail closed).
   Log: time, principal, tool, SQL text, verdict + reason, row count, truncated, duration.
   Never log result data, tokens, or secrets.
10. **Query results are untrusted data.** Returned to the client clearly labelled as data.
    Residual risk (document, don't hide): a client with other tools (web fetch, email) could
    exfiltrate rows the principal can legitimately read. The server bounds *what* can be read, not
    what the client does with it.
11. No secrets in the repo. `.env.example` has placeholders only. `.env*` (except `.env.example`) is gitignored.

## 3. Stack (decided — do not swap without asking)

| Concern | Choice | Why |
|---|---|---|
| Language | Python 3.12, `uv`, `exclude-newer` cutoff | Same as zero-trust-rag; reproducible |
| MCP | Official `mcp` Python SDK (FastMCP), pinned | Reference implementation of the spec |
| Transport | stdio first; Streamable HTTP + bearer JWT in Phase 5 | stdio = Claude Desktop/Code demo; HTTP = multi-user story |
| SQL parsing | `pglast` (libpg_query = Postgres's own parser). Has Windows wheels | No parser differential vs the real server (why not `sqlglot` → ADR) |
| DB | PostgreSQL 18 (`postgres:18.6` image, pinned by digest) + pgcrypto | RLS, column grants, role GUCs are native. pglast 8.x parses with the PG 18 grammar; same major = no parser differential |
| Driver | `psycopg` 3 + `psycopg_pool` (async). Raw SQL, no ORM | |
| Auth | JWT HS256 via `pyjwt`, pluggable verifier | Same model as zero-trust-rag |
| Tests | `pytest`, `pytest-asyncio`; MCP tests via the SDK's in-memory client session | |
| Quality | `ruff` (lint + format), `mypy --strict` on `app/` | |
| Logging | `structlog` JSON to **stderr** (stdout is the stdio MCP channel) | |
| CI | GitHub Actions: ruff, mypy, pytest with Postgres service; actions pinned to SHAs | |

No LLM SDK is needed: the MCP *client* (Claude Desktop, Claude Code, MCP Inspector) is the model.
Tests never call a paid API.

## 4. Data model (demo dataset, schema `shop`)

```
shop.tenants(id uuid pk, name text)
shop.users(id uuid pk, email citext unique, display_name text)
shop.memberships(tenant_id, user_id, role text check in ('analyst','admin'), pk(tenant_id,user_id))
shop.customers(id, tenant_id, name, country, email, phone, created_at, unique(id, tenant_id))
       -- mcp_reader is granted SELECT(id, tenant_id, name, country, created_at) only: email/phone never
shop.products(id, tenant_id, name, category, price_cents)
shop.orders(id, tenant_id, customer_id, status, total_cents, created_at,
       fk(customer_id, tenant_id) -> customers(id, tenant_id))
shop.order_items(order_id, tenant_id, product_id, qty, unit_price_cents)
private.context_key(key bytea)          -- SELECT only for mcp_rls_helper
audit.tool_calls(id bigserial, at, user_id, tenant_id, tool, sql_text, verdict, reason,
       row_count, truncated, duration_ms)   -- INSERT only for mcp_auditor
```

**Read rule:** row's `tenant_id` = verified context tenant AND verified user is a member of it.
Roles: `mcp_migrator` (owner, BYPASSRLS), `mcp_rls_helper` (NOLOGIN, BYPASSRLS, owns helpers),
`mcp_reader` (runtime), `mcp_auditor` (audit insert only).

## 5. MCP tools (keep it this small)

- `list_tables()` → allowlisted tables/views and their **granted** columns only.
- `describe_table(name)` → columns + types for one allowlisted table (granted columns only).
- `run_query(sql)` → validated read-only query; returns `columns`, `rows`, `row_count`, `truncated`.

Rejections return a structured, model-readable reason (e.g. `function_not_allowed: pg_sleep`) and never
leak internal errors, role names, or the context key.

## 6. Known hard problems — document them, test them

- **set_config impersonation** (rule 4): test that a forged/unsigned/expired context returns zero rows,
  with the validator disabled.
- **Validator bypass classes**: adversarial corpus in `tests/validator/corpus/` (multi-statement,
  `COMMIT;` escape, writable CTE, `SELECT INTO`, `FOR UPDATE`, quoted / `U&""` identifiers, comments,
  dollar quoting, functions hidden in `ORDER BY` / `LATERAL` / `VALUES` / subqueries, catalog reads,
  `reg*` casts). Every entry has an expected verdict.
- **Resource exhaustion**: cross-join / huge sort is stopped by `statement_timeout` / `temp_file_limit`
  even with the validator disabled.
- **Views bypassing RLS** (rule 8).

## 7. Repo layout (target)

```
app/
  config.py          # pydantic-settings
  auth.py            # JWT verify -> Principal
  context.py         # sign/verify the DB context token (must match db helper)
  db.py              # pools (reader, auditor) + read_only_transaction(principal)
  validator.py       # pglast-based policy: Verdict(allowed, reason)
  executor.py        # validate -> execute bounded -> audit
  audit.py
  server.py          # FastMCP tools + transports
db/bootstrap/        # roles, databases, extensions, role GUCs (superuser, once)
db/migrations/       # 001_schema.sql, 002_grants.sql, 003_rls.sql, 004_audit.sql ...
scripts/             # migrate.py, seed.py, demo.py
tests/
  validator/         # pure unit tests + adversarial corpus (no DB)
  db/                # RLS / grants / read-only / timeout tests as mcp_reader, validator OFF
  mcp/               # tool tests via in-memory MCP client
docs/                # threat-model.md, decisions/ (ADRs)
```

## 8. Commands (keep this section accurate as the project evolves)

```
cp .env.example .env             # then replace every change-me
docker compose up -d db
uv sync
uv run python scripts/migrate.py
uv run python scripts/seed.py
uv run pytest
uv run ruff check . && uv run ruff format --check . && uv run mypy app
uv run python -m app.server      # stdio MCP server (for Claude Desktop / Claude Code / MCP Inspector)
```

## 9. How to work in this repo

- Work **one phase at a time**. Start in plan mode; wait for approval before writing code.
- Every security property gets **both** an "allowed" test and a "denied" test.
- DB-layer properties are tested **with the validator bypassed** — the database must hold on its own.
- After each phase: run the full test suite and show the actual output. Never claim tests pass without running them.
- Small, meaningful conventional commits. Do not commit for Haris unless asked. Never rewrite history.
- Never run git push, git remote add, or any gh command. Haris pushes manually after Phase 5.
  Local commits only, and only when Haris asks.
- If a requirement is ambiguous or a decision in §3 seems wrong, **stop and ask** instead of guessing.
- Do not add features not in the current phase. No Redis, Kubernetes, write tools, NL-to-SQL agent, or UI.
- README must separate **Implemented / Tested** from **Planned**. Never write "production-ready",
  "enterprise-grade", "compliant", or invented metrics.
- Explain non-obvious decisions in short code comments or an ADR in `docs/decisions/`.

## 10. Phases

0. Scaffold: uv project, ruff/mypy, compose, CI skeleton, config, logging to stderr.
1. Database: bootstrap roles + role GUCs, schema, column grants, signed-context helper, RLS, audit table,
   seed. Tests as `mcp_reader` with no validator: allow/deny per tenant, forged context, writes blocked,
   column grants, timeout, views.
2. Validator: pglast policy + adversarial corpus. Pure unit tests.
3. Executor: read-only txn, bounded fetch, error mapping, audit (fail closed). Integration tests.
4. MCP server over stdio: three tools, startup token verification, in-memory client tests,
   Claude Desktop / Code config example.
5. Streamable HTTP + per-request bearer JWT (two principals, one process, isolation test).
6. Docs + demo: ADRs, threat model, README with Mermaid diagrams, `scripts/demo.py`, demo video.
