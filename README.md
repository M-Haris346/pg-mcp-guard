# pg-mcp-guard

An MCP (Model Context Protocol) server that lets an LLM agent run **read-only SQL** against
PostgreSQL. Safety is enforced by **the database first** (a least-privilege role, column grants,
row-level security keyed to a signed identity context, role-level timeouts) and by a SQL validator
built on Postgres's own parser second — never by the prompt.

## Why

The archived reference Postgres MCP server ran model-written SQL inside a `READ ONLY` transaction,
and a multi-statement string (`COMMIT; DROP ...`) escaped it. See Datadog Security Labs,
"MCP vulnerability case study: SQL injection in the PostgreSQL MCP server". This repo shows a
layered fix, with tests for each layer, including tests that run attacks with the validator
disabled to show the database holds on its own.

## Implemented / Tested

- Phase 0 scaffold: `uv` project with dependency cutoff and exact pins for `mcp` and `pglast`
  ([ADR 0001](docs/decisions/0001-dependency-pinning.md)), ruff, `mypy --strict`, Postgres 18
  compose service pinned by digest, CI skeleton.
- JSON logging to stderr only (stdout is the stdio MCP channel) — tested.
- Phase 1 database layer. Every item below is tested as `mcp_reader` with **no validator**
  (`tests/db/`):
  - Roles `mcp_migrator`, `mcp_rls_helper`, `mcp_reader`, `mcp_auditor`. The reader is not a
    superuser, cannot bypass RLS and owns nothing. Its role-level limits are read-only by default,
    `statement_timeout`, `lock_timeout`, `idle_in_transaction_session_timeout`, `temp_file_limit`
    (which only a superuser can change) and a connection limit.
  - Tenant isolation through `ENABLE` + `FORCE` RLS on every `shop` table, keyed to an
    HMAC-signed, short-lived context that the database verifies
    ([ADR 0002](docs/decisions/0002-signed-rls-context.md)). Forged, tampered, expired and
    malformed contexts see zero rows.
  - Column grants: customer email and phone are never readable.
  - Writes are blocked twice, by the read-only transaction and by the missing privileges.
    The `COMMIT; DROP ...` escape fails.
  - Sessions sharing one role cannot read each other's query text (`pg_stat_activity` revoked).
  - Every exposed view is `security_invoker`. A test shows a default view leaking rows across
    tenants, which is why the rule exists.
  - Append-only audit table: `mcp_auditor` may only insert.
  - Known gap, documented and tested: with the validator off, the reader can lower its own
    `statement_timeout`. Phase 3 adds the mitigation.

## Planned

2. Validator: `pglast` policy and adversarial corpus.
3. Executor: read-only transaction, bounded fetch, error mapping, fail-closed audit.
4. MCP server over stdio: `list_tables`, `describe_table`, `run_query`.
5. Streamable HTTP with per-request bearer JWT.
6. Threat model, ADRs, demo.

## Development

```
cp .env.example .env             # then replace every change-me
docker compose up -d db          # first start runs db/bootstrap (roles, databases)
uv sync
uv run python scripts/migrate.py
uv run python scripts/seed.py
uv run pytest                    # migrates and seeds its own mcpguard_test database
uv run ruff check . && uv run ruff format --check . && uv run mypy app
```
