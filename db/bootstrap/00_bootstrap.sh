#!/usr/bin/env bash
# One-time database bootstrap. Runs as the Postgres superuser:
#   - docker compose: automatically on first start (empty data volume), via
#     /docker-entrypoint-initdb.d
#   - CI: directly, with PGHOST/PGUSER/PGPASSWORD pointing at the service container
#
# Creates the four roles, their role-level limits, the two databases, the
# extensions, and the per-database hardening that only a superuser can do.
# Everything else (schemas, tables, grants, RLS) is in db/migrations and runs as
# mcp_migrator.
#
# Re-runnable: roles and databases are created only if missing; attributes,
# passwords, settings and revokes are (re)applied every time.
#
# No `set -u`: the postgres image *sources* this file from its entrypoint when
# it is not executable, and -u would leak into the entrypoint's own shell.
set -eo pipefail

: "${MCP_MIGRATOR_PASSWORD:?MCP_MIGRATOR_PASSWORD is required}"
: "${MCP_READER_PASSWORD:?MCP_READER_PASSWORD is required}"
: "${MCP_AUDITOR_PASSWORD:?MCP_AUDITOR_PASSWORD is required}"

BOOTSTRAP_PSQL=(psql -v ON_ERROR_STOP=1 --no-psqlrc --quiet
    --username "${PGUSER:-${POSTGRES_USER:-postgres}}")

# Passwords are passed as psql variables and expanded with :'name', which
# quotes them as SQL literals. They are never pasted into the SQL text.
"${BOOTSTRAP_PSQL[@]}" --dbname postgres \
    -v migrator_pw="$MCP_MIGRATOR_PASSWORD" \
    -v reader_pw="$MCP_READER_PASSWORD" \
    -v auditor_pw="$MCP_AUDITOR_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE %I', r)
FROM unnest(ARRAY['mcp_migrator', 'mcp_rls_helper', 'mcp_reader', 'mcp_auditor']) AS r
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r)
\gexec

-- Owner of the databases, schemas and tables. BYPASSRLS so migrations and the
-- seed are not filtered by the policies they create.
ALTER ROLE mcp_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
    BYPASSRLS PASSWORD :'migrator_pw';

-- Owns only the SECURITY DEFINER context helper. NOLOGIN: nobody connects as it.
-- BYPASSRLS so the helper can read shop.memberships regardless of policies.
ALTER ROLE mcp_rls_helper NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
    BYPASSRLS;

-- Runtime role for model-written SQL. Owns nothing; SELECT-only grants come
-- from migrations.
ALTER ROLE mcp_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
    NOBYPASSRLS NOINHERIT CONNECTION LIMIT 10 PASSWORD :'reader_pw';

-- Writes audit rows only (INSERT on audit.tool_calls, from migrations).
ALTER ROLE mcp_auditor LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
    NOBYPASSRLS NOINHERIT CONNECTION LIMIT 5 PASSWORD :'auditor_pw';

-- Role-level limits: apply to every session of the role, before any query runs.
ALTER ROLE mcp_reader SET default_transaction_read_only = on;
ALTER ROLE mcp_reader SET statement_timeout = '5s';
ALTER ROLE mcp_reader SET lock_timeout = '1s';
ALTER ROLE mcp_reader SET idle_in_transaction_session_timeout = '10s';
-- temp_file_limit is a superuser-only setting: mcp_reader cannot raise it,
-- even with SET or set_config. It is the hard backstop for spilling queries.
ALTER ROLE mcp_reader SET temp_file_limit = '64MB';
ALTER ROLE mcp_reader SET search_path = shop;

ALTER ROLE mcp_auditor SET statement_timeout = '2s';
ALTER ROLE mcp_auditor SET lock_timeout = '1s';

-- mcp_migrator creates the helper function and then hands ownership to
-- mcp_rls_helper; that needs SET ROLE rights. INHERIT FALSE: the migrator does
-- not silently gain the helper's privileges.
GRANT mcp_rls_helper TO mcp_migrator WITH INHERIT FALSE, SET TRUE;

SELECT format('CREATE DATABASE %I OWNER mcp_migrator', d)
FROM unnest(ARRAY['mcpguard', 'mcpguard_test']) AS d
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = d)
\gexec
SQL

for db in mcpguard mcpguard_test; do
    "${BOOTSTRAP_PSQL[@]}" --dbname "$db" <<'SQL'
-- Only our roles may connect. Revoking ALL from PUBLIC also removes the default
-- TEMPORARY privilege, so mcp_reader cannot create temp tables.
REVOKE ALL ON DATABASE :"DBNAME" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"DBNAME" TO mcp_migrator, mcp_reader, mcp_auditor;

-- Nothing lives in public; nobody but its owner (the DB owner) may use it.
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- Extensions live in their own schema. mcp_reader gets no USAGE on it.
CREATE SCHEMA IF NOT EXISTS ext;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA ext;
CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA ext;
REVOKE ALL ON SCHEMA ext FROM PUBLIC;
GRANT USAGE ON SCHEMA ext TO mcp_migrator, mcp_rls_helper;

-- Every mcp_reader session runs as the same role, and Postgres lets a role see
-- the query text of its own other sessions. Without these revokes one
-- principal's session could read another's SQL. pg_catalog is per database,
-- so this runs in each one.
REVOKE SELECT ON pg_catalog.pg_stat_activity FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_stat_get_activity(integer) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_stat_get_backend_activity(integer) FROM PUBLIC;

-- A role may cancel or terminate its own other backends. Since every principal
-- is mcp_reader, one principal could kill another's queries or sessions
-- (cross-session DoS). Also hide the backend id -> pid listing.
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_cancel_backend(integer) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_terminate_backend(integer, bigint) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_stat_get_backend_idset() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_stat_get_backend_pid(integer) FROM PUBLIC;

-- set_config is the only way a SELECT can change a setting. Without these two
-- lines, model SQL that slipped past the validator could lift its own
-- work_mem, idle_in_transaction_session_timeout, statement_timeout or
-- lock_timeout for the session (ADR 0002, gap check). Granted back only to:
--   mcp_rls_helper: owns the SECURITY DEFINER ctx.set_context(), which sets
--                   mcpguard.ctx (and nothing else) for the executor.
-- Not granted to mcp_migrator (no migration or script calls it; run pg_dump,
-- which does, as the superuser), mcp_reader or mcp_auditor.
-- db/upgrade/001_revoke_set_config.sh applies the same to existing databases.
REVOKE EXECUTE ON FUNCTION pg_catalog.set_config(text, text, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pg_catalog.set_config(text, text, boolean) TO mcp_rls_helper;

-- Large objects are the one storage write that needs no table grant. Remove
-- the functions that create, modify or delete them.
REVOKE EXECUTE ON FUNCTION
    pg_catalog.lo_creat(integer),
    pg_catalog.lo_create(oid),
    pg_catalog.lo_from_bytea(oid, bytea),
    pg_catalog.lo_put(oid, bigint, bytea),
    pg_catalog.lowrite(integer, bytea),
    pg_catalog.lo_truncate(integer, integer),
    pg_catalog.lo_truncate64(integer, bigint),
    pg_catalog.lo_unlink(oid),
    pg_catalog.lo_import(text),
    pg_catalog.lo_import(text, oid),
    pg_catalog.lo_export(oid, text)
FROM PUBLIC;
SQL
done
