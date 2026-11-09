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

- `app/context.py` signs. `ctx.current_tenant_id()` verifies. It was created as
  `private.current_tenant_id()` in `db/migrations/002_rls_helper.sql` and moved to the `ctx` schema
  by `007_context_schema.sql`. Signer and verifier must stay in sync.
- The key lives in `private.context_key`. Only `mcp_rls_helper` (NOLOGIN) can read it. The helper
  is `SECURITY DEFINER`, owned by that role, and has a fixed `search_path`.
- The helper returns the tenant id only if **all** of these hold:
  - the shape is valid (regex-checked before any cast);
  - the HMAC matches;
  - `now() < exp <= now() + 300s`;
  - the user is a member of the tenant (`shop.memberships`).

  Otherwise it returns NULL. Policies compare `tenant_id = (SELECT ctx.current_tenant_id())`,
  and NULL matches no row: **fail closed, no error**.
- The token is set transaction-local through `ctx.set_context(token)` and always as a **bind
  parameter**, never interpolated into SQL text (CLAUDE.md rule 4). Query text is visible in logs
  and statistics views. `ctx.set_context` is a `SECURITY DEFINER` function owned by
  `mcp_rls_helper`; it calls `set_config('mcpguard.ctx', token, true)` and sets nothing else.
- **`mcp_reader` may not call `set_config` at all** (see "Gap check" below). `ctx` is the only
  schema besides `shop` the reader can use. It holds exactly the two functions above, and the
  reader has no USAGE on `private`, which holds only the key table.
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

## Gap check (Phase 6): settings the reader could change

Our own Phase 6 gap check asked: with the validator off, can model SQL lift its own limits with
`set_config(name, value, false)`, and what bounds it if so? Measured against the real executor
(`statement_timeout` 3 s via SET LOCAL, deadline 4 s, 50-row fetch batches) **before** the fix:

| Attempt (validator off) | Result | Bounded by |
|---|---|---|
| A: `statement_timeout` → 0, then `pg_sleep(10)` in the same FETCH | `query_timeout` after 3.03 s, connection reused | the server timer, armed when the FETCH started (before `set_config` ran) |
| B: `statement_timeout` → 0, slow work in the 2nd FETCH | `query_timeout` after 4.03 s, connection replaced | the executor deadline only |
| C': `lock_timeout` and `statement_timeout` → 0, advisory-lock wait in the 2nd FETCH | `query_timeout` after 4.03 s, connection replaced | the executor deadline only (table locks are taken at DECLARE, before the change) |
| D: `work_mem` → 2 GB | accepted | **time only; memory unbounded** (`temp_file_limit` covers disk, not RAM) |
| E: `idle_in_transaction_session_timeout` → 0, then idle 12 s in a transaction | session stays alive (control: killed at 10 s) | **nothing at the DB layer** if the server process stalls mid-transaction; the backend would hold its locks indefinitely |

**Fix (bootstrap + `db/upgrade/001_revoke_set_config.sh` + migration 007):**
- `REVOKE EXECUTE ON FUNCTION pg_catalog.set_config(text, text, boolean) FROM PUBLIC`, granted back
  only to `mcp_rls_helper`, the owner of `ctx.set_context`. The migrator gets no grant: no
  migration or script calls `set_config` (run `pg_dump`, which does, as the superuser).
- The executor sets its limits with plain `SET LOCAL statement_timeout = <int>` and so on, built
  only from validated positive integers, and the context through `ctx.set_context(%s)`.
- Model SQL runs only as `DECLARE … CURSOR FOR <sql>` over the extended protocol, so a `SET`
  statement cannot get in, and `set_config` is the only way a SELECT can change a setting. The
  whole class is therefore closed at the database layer: every attempt above now fails at once
  with `function_not_allowed: set_config`, and is audited.
- **Startup fails closed:** if `has_function_privilege(current_user, 'pg_catalog.set_config(...)',
  'EXECUTE')` is true for the reader, the server refuses to start (`reader_can_set_config`), on
  stdio and on HTTP.

Tests: `tests/db/test_set_config.py` and `tests/executor/test_timeout_gucs.py`. **Mutation check:**
with `set_config` granted back to PUBLIC, 22 of these tests fail and the server refuses to start;
restored, they pass.

**Found along the way:** migration 002's `REVOKE ALL ON FUNCTION private.current_tenant_id() FROM
PUBLIC` never took effect. It ran after the function's ownership had passed to `mcp_rls_helper`, and
a grant or revoke by a non-owner is a silent no-op (a WARNING, not an error). Harmless (without a
valid context the helper returns NULL), but the documented ACL was wrong. Migration 007 issues the
grants as the owner, and a test now asserts the exact ACL of both `ctx` functions.

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
3. **Lifting limits from model SQL: closed** (Phase 6, see "Gap check" above). Before the fix,
   `set_config(..., false)` let model SQL with the validator off lift `statement_timeout`,
   `lock_timeout`, `work_mem` and `idle_in_transaction_session_timeout`. Now it is refused at the
   database layer, and the server refuses to start if the revoke is missing.
4. **Session state on pooled connections.** Model SQL (with the validator off) can still take
   session advisory locks, which survive ROLLBACK. Settings can no longer be changed (item 3). On a
   pooled connection the lock would carry over to the next principal, so every connection returned
   to the pool gets `DISCARD ALL` (Phase 3, tested).
5. **Pids are still visible in `pg_locks`.** `pg_locks` (via `pg_lock_status()`) lists the pid of
   every backend holding a lock, which includes every open transaction. With cancel/terminate
   revoked, a pid alone gives no capability, and the validator will not allow `pg_catalog` reads.
   Not revoked in Phase 1.
6. **Key compromise.** Anyone with the key can sign any context. The key is in the server's
   environment and in `private.context_key`. Rotation: change `MCP_CONTEXT_KEY` and re-run
   `scripts/migrate.py`. Outstanding tokens die within 300 s at most.
