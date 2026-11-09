# ADR 0002: Signed RLS context

Status: accepted (Phase 1)

## Context

Row-level security policies need to know *who* is asking. The usual pattern is a custom GUC:
the application runs `set_config('app.tenant_id', '<uuid>', true)` and policies read it with
`current_setting('app.tenant_id')`.

Here that is not enough. The SQL comes from a model, and `set_config` is an ordinary function
any role may call. One query such as

```sql
SELECT set_config('app.tenant_id', '<other tenant>', true), * FROM shop.orders
```

would impersonate another tenant. The validator rejects `set_config` (Phase 2), but the core claim
of this project is that the database holds **even if the validator has a bug**.

## Decision

The GUC `mcpguard.ctx` carries a signed, short-lived token, and the database verifies it.

```
v1.<tenant_uuid>.<user_uuid>.<exp_unix_seconds>.<hex HMAC-SHA256(key, "v1.<tenant>.<user>.<exp>")>
```

- `app/context.py` signs. `private.current_tenant_id()` (`db/migrations/002_rls_helper.sql`)
  verifies. Both must stay in sync.
- The key lives in `private.context_key`. Only `mcp_rls_helper` (NOLOGIN) can read it. The helper
  is `SECURITY DEFINER`, owned by that role, and has a fixed `search_path`.
- The helper returns the tenant id only if **all** of these hold:
  - the shape is valid (regex-checked before any cast);
  - the HMAC matches;
  - `now() < exp <= now() + 300s`;
  - the user is a member of the tenant (`shop.memberships`).

  Otherwise it returns NULL. Policies compare `tenant_id = (SELECT private.current_tenant_id())`,
  and NULL matches no row: **fail closed, no error**.
- The token is set transaction-local (`set_config(..., true)`) and always as a **bind parameter**,
  never interpolated into SQL text (CLAUDE.md rule 4). Query text is visible in logs and statistics
  views.
- All principals share the role `mcp_reader`, and Postgres shows a role its own other sessions'
  query text. The bootstrap therefore revokes `pg_stat_activity`, `pg_stat_get_activity(integer)`
  and `pg_stat_get_backend_activity(integer)` from `PUBLIC`.
- The same shared role would let one principal **cancel or terminate another's backend**: a
  role may signal its own other sessions by default, and pids are small, guessable integers.
  That is a cross-session DoS. The bootstrap revokes `pg_cancel_backend(integer)` and
  `pg_terminate_backend(integer, bigint)` from `PUBLIC`. It also revokes
  `pg_stat_get_backend_idset()` and `pg_stat_get_backend_pid(integer)`, so the stats functions do
  not list pids. Tested in `tests/db/test_grants.py`: the attacker is handed the victim's pid
  directly, and the victim's running query and its session both survive.

Tested in `tests/db/test_rls.py` and `tests/db/test_grants.py` as `mcp_reader` with no validator.
Forged, tampered, expired, over-long-lived, wrong-key and malformed tokens all see zero rows.

## Alternatives rejected

- **One database role per tenant / user** (`SET ROLE`). Strong, but role count grows with users,
  grants must be managed per role, and `SET ROLE` from model SQL becomes its own attack surface.
- **Plain GUC + validator only.** A single validator bug means full cross-tenant access.
- **JWT verification inside Postgres.** Needs an extension or a large PL/pgSQL JSON/base64
  parser. A fixed-format HMAC token is simpler to review.

## Residual risks

1. **Replay of the principal's own token.** Model SQL can read its own token (with the validator
   off) and set it again within its lifetime (≤ 300 s, default 60 s). This grants nothing beyond
   the same principal and tenant. Tested as the "allowed" case.
2. **Non-constant-time signature comparison.** The bytea `<>` in PL/pgSQL is not constant-time. A
   timing attack would need many thousands of precisely timed queries through the MCP server, each
   through the executor, network and audit log, to recover a per-message HMAC that expires within
   minutes. We judge this impractical and accept it.
3. **The model can lower its own `statement_timeout`.** `statement_timeout` is user-settable.
   With the validator off, `SET statement_timeout = 0` followed by a CPU-only query (one that
   writes no temp files) is unbounded at the database layer. `temp_file_limit` (superuser-only)
   still stops spilling queries, and that is tested. The CPU-only gap is recorded as a test marked
   `known_gap` (`tests/db/test_limits.py`). Mitigations, Phase 3 / Phase 2:
   - the executor sets `SET LOCAL statement_timeout` in every transaction and enforces its own
     client-side deadline, cancelling the query on the server when it passes;
   - the executor resets pooled connections, so session-level changes do not persist;
   - the validator rejects `SET`, `set_config` and every function not on its allowlist.
4. **Session state on pooled connections.** Model SQL (with the validator off) can set
   session-level state: `set_config(..., false)` for any user-settable GUC, including
   `mcpguard.ctx`, and session advisory locks. On a pooled connection this would carry over to
   the next principal. Phase 3 requirement: run `DISCARD ALL` on every connection returned to the
   pool, and test it.
5. **Pids are still visible in `pg_locks`.** `pg_locks` (via `pg_lock_status()`) lists the pid of
   every backend holding a lock, which includes every open transaction. With cancel/terminate
   revoked, a pid alone gives no capability, and the validator will not allow `pg_catalog` reads.
   Not revoked in Phase 1.
6. **Key compromise.** Anyone with the key can sign any context. The key is in the server's
   environment and in `private.context_key`. Rotation: change `MCP_CONTEXT_KEY` and re-run
   `scripts/migrate.py`. Outstanding tokens die within 300 s at most.
