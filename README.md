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

## Planned

1. Database: roles with role-level limits, schema, column grants, HMAC-signed RLS context, audit table, seed.
2. Validator: `pglast` policy and adversarial corpus.
3. Executor: read-only transaction, bounded fetch, error mapping, fail-closed audit.
4. MCP server over stdio: `list_tables`, `describe_table`, `run_query`.
5. Streamable HTTP with per-request bearer JWT.
6. Threat model, ADRs, demo.

## Development

```
cp .env.example .env             # then replace every change-me
docker compose up -d db
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check . && uv run mypy app
```
