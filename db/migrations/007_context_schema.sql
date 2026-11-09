-- Phase 6 gap fix (ADR 0002): the reader can no longer call set_config at all
-- (bootstrap / db/upgrade/001), so the executor sets the signed context through
-- a narrow SECURITY DEFINER function instead, in a new schema "ctx".
--
-- ctx holds exactly two functions, both owned by mcp_rls_helper:
--   ctx.set_context(token)   sets mcpguard.ctx, transaction-local, nothing else
--   ctx.current_tenant_id()  the RLS helper (moved here from private)
-- mcp_reader gets USAGE on ctx and EXECUTE on both; it loses USAGE on private,
-- which now holds only the context key table.

CREATE SCHEMA ctx;

CREATE FUNCTION ctx.set_context(token text)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
-- Fixed search_path for the definer function. This SET clause only scopes
-- search_path to the call; mcpguard.ctx set below survives until the end of
-- the transaction, as intended.
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    -- Hard-coded name and is_local = true: callers can set the context for
    -- their own transaction and nothing else. The value is untrusted: the RLS
    -- helper verifies the signature, expiry and membership on every read.
    PERFORM pg_catalog.set_config('mcpguard.ctx', token, true);
END;
$$;

-- Hand both functions to mcp_rls_helper. The new owner needs CREATE on the
-- schema at that moment (as in 002), and USAGE to name objects in it while
-- acting as that role below; both are granted only for these statements.
GRANT USAGE, CREATE ON SCHEMA ctx TO mcp_rls_helper;
ALTER FUNCTION ctx.set_context(text) OWNER TO mcp_rls_helper;

-- Moving a function needs its owner's rights; the migrator may SET ROLE to
-- mcp_rls_helper (bootstrap: INHERIT FALSE, SET TRUE). RLS policies refer to
-- the function by OID, so they keep working after the move.
SET ROLE mcp_rls_helper;
ALTER FUNCTION private.current_tenant_id() SET SCHEMA ctx;
-- Function privileges must be granted by the owner. Run as the migrator after
-- the ownership change they are silent no-ops (a WARNING, not an error):
-- that is how 002's "REVOKE ... FROM PUBLIC" never took effect, leaving
-- current_tenant_id() executable by PUBLIC. Both are fixed here, and
-- tests/db/test_set_config.py asserts the exact ACLs.
REVOKE ALL ON FUNCTION ctx.set_context(text), ctx.current_tenant_id() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctx.set_context(text), ctx.current_tenant_id() TO mcp_reader;
RESET ROLE;

REVOKE USAGE, CREATE ON SCHEMA ctx FROM mcp_rls_helper;
GRANT USAGE ON SCHEMA ctx TO mcp_reader;

REVOKE USAGE ON SCHEMA private FROM mcp_reader;
