# Connecting an MCP client (stdio)

The server runs as a subprocess of the MCP client and talks JSON-RPC over stdin/stdout. It reads
its settings from `.env` in the repository directory, and its **principal** (who you are) from
`MCP_PRINCIPAL_TOKEN`.

> **Dev only. The token sits in plain text in the client's config file.**
> - Mint a **short-lived** token (`--ttl 1h` or less; the server refuses anything over
>   `JWT_MAX_LIFETIME_SECONDS`, 12 h by default) and mint a new one when it expires.
> - **Never put `JWT_SECRET`, `MCP_CONTEXT_KEY` or database passwords in the client config.** They
>   stay in `.env`. Anyone holding `JWT_SECRET` can mint any identity (see ADR 0005).
> - Don't commit client configs that contain a token.

## 1. Prerequisites

```
cp .env.example .env              # replace every change-me; APP_ENV=dev for the token script
docker compose up -d db
uv sync
uv run python scripts/migrate.py
uv run python scripts/seed.py
```

## 2. Mint a principal token

```
uv run python -m scripts.mint_token --user alice --tenant acme --ttl 1h
```

- **Users:** `alice` (acme), `bob` (globex), `carol` (acme and globex), `mallory` (no tenant, so
  the server refuses to start with her token). UUIDs work too.
- **Output:** the script prints only the token on stdout.
- **Dev only:** it refuses to run unless `APP_ENV=dev`.

## 3. Configure the client

Replace `D:/github/pg-mcp-guard` with your checkout path and `<token>` with the minted token.

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "pg-mcp-guard": {
      "command": "uv",
      "args": ["run", "--directory", "D:/github/pg-mcp-guard", "python", "-m", "app.server"],
      "env": { "MCP_PRINCIPAL_TOKEN": "<token>" }
    }
  }
}
```

`uv run --directory` makes that directory the working directory, so the server finds `.env`.

**Claude Code:**

```
claude mcp add pg-mcp-guard -e MCP_PRINCIPAL_TOKEN=<token> -- uv run --directory D:/github/pg-mcp-guard python -m app.server
```

**MCP Inspector:**

```
npx @modelcontextprotocol/inspector -e MCP_PRINCIPAL_TOKEN=<token> uv run --directory D:/github/pg-mcp-guard python -m app.server
```

## 4. What to expect

- **Three tools:** `list_tables`, `describe_table`, `run_query`. Start with `list_tables`.
- **Results** are labelled as untrusted data and fenced in `<untrusted-data>` … `</untrusted-data>`.
- **Refusals** carry a short reason, e.g. `function_not_allowed: pg_sleep`, `column_not_allowed`,
  `relation_not_allowed: users`, `principal_token_expired`.
- **If the server does not start,** the client shows it as failed. The reason is the last JSON line
  the server wrote to stderr (`"event": "startup_failed"`), e.g.
  `invalid_principal_token: expired` or `principal_not_a_member`. Claude Desktop keeps it in its MCP
  log file.
