# Architecture decision records

| ADR | Decision |
|---|---|
| [0001](0001-dependency-pinning.md) | Resolution cutoff (`exclude-newer`), exact pins for `mcp` and `pglast`, Postgres image pinned by digest at the parser's major version (18.6). |
| [0002](0002-signed-rls-context.md) | RLS keyed to an HMAC-signed, short-lived context verified in the database; the reader may not call `set_config` (Phase 6 gap check). |
| [0003](0003-validator-pglast.md) | SQL validator on Postgres's own parser (pglast), deny by default on node types, relations, functions, types and operators. |
| [0004](0004-executor.md) | Executor: read-only transaction, server-side cursor, bounded fetch, client deadline with cancel and backstop, fail-closed audit. |
| [0005](0005-mcp-server.md) | stdio MCP server: principal from a token verified at startup, strict tool inputs, untrusted-data fence. |
| [0006](0006-http-transport.md) | Streamable HTTP: bearer token on every request via the SDK's auth path; stdio vs HTTP trust model. |
