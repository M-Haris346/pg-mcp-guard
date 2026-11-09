-- Signed RLS context (CLAUDE.md rule 4, ADR 0002).
--
-- The executor sets the GUC mcpguard.ctx, transaction-local, to a token:
--     v1.<tenant_uuid>.<user_uuid>.<exp_unix_seconds>.<hex hmac>
-- hmac = HMAC-SHA256(private.context_key.key, 'v1.<tenant>.<user>.<exp>')
-- (signed by app/context.py, which must stay in sync with this function).
--
-- Model-written SQL can call set_config('mcpguard.ctx', ...) itself, so the
-- GUC is untrusted input. This function trusts it only if the signature,
-- expiry and membership all check out. Anything else returns NULL, and the
-- policies compare tenant_id = NULL, which matches no row: fail closed.

CREATE FUNCTION private.current_tenant_id()
RETURNS uuid
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
-- Fixed search_path: a SECURITY DEFINER function must not resolve names
-- through the caller's search_path. Everything below is schema-qualified.
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    -- Longest valid token is 2+1+36+1+36+1+12+1+64 = 154 characters.
    max_token_length  constant integer := 200;
    -- Even a correctly signed token may not live longer than this.
    max_ttl_seconds   constant bigint  := 300;
    uuid_pattern      constant text    :=
        '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';

    v_token     text := current_setting('mcpguard.ctx', true);  -- NULL if never set
    v_parts     text[];
    v_key       bytea;
    v_exp       bigint;
    v_now       bigint;
    v_tenant_id uuid;
    v_user_id   uuid;
BEGIN
    IF v_token IS NULL OR v_token = '' OR length(v_token) > max_token_length THEN
        RETURN NULL;
    END IF;

    v_parts := string_to_array(v_token, '.');
    -- Validate the shape with regexes *before* any cast, so malformed input
    -- returns NULL instead of raising an error.
    IF cardinality(v_parts) <> 5
       OR v_parts[1] <> 'v1'
       OR v_parts[2] !~ uuid_pattern
       OR v_parts[3] !~ uuid_pattern
       OR v_parts[4] !~ '^[0-9]{1,12}$'
       OR v_parts[5] !~ '^[0-9a-f]{64}$' THEN
        RETURN NULL;
    END IF;

    SELECT k.key INTO v_key FROM private.context_key AS k;
    IF v_key IS NULL THEN
        RETURN NULL;
    END IF;

    -- Not a constant-time comparison; see ADR 0002 for why that is acceptable here.
    IF ext.hmac(convert_to(array_to_string(v_parts[1:4], '.'), 'UTF8'), v_key, 'sha256')
       <> decode(v_parts[5], 'hex') THEN
        RETURN NULL;
    END IF;

    -- now() is the transaction start time, so the answer is stable for the
    -- whole transaction.
    v_exp := v_parts[4]::bigint;
    v_now := extract(epoch FROM now())::bigint;
    IF v_exp <= v_now OR v_exp > v_now + max_ttl_seconds THEN
        RETURN NULL;
    END IF;

    v_tenant_id := v_parts[2]::uuid;
    v_user_id   := v_parts[3]::uuid;
    IF NOT EXISTS (
        SELECT 1 FROM shop.memberships AS m
         WHERE m.tenant_id = v_tenant_id AND m.user_id = v_user_id
    ) THEN
        RETURN NULL;
    END IF;

    RETURN v_tenant_id;
END;
$$;

-- The helper's owner (the identity it runs as) needs only these reads.
GRANT USAGE ON SCHEMA private, shop TO mcp_rls_helper;
GRANT SELECT ON private.context_key TO mcp_rls_helper;
GRANT SELECT ON shop.memberships TO mcp_rls_helper;

-- Hand ownership to mcp_rls_helper. Postgres requires the new owner to hold
-- CREATE on the schema at that moment; grant it only for the ALTER.
GRANT CREATE ON SCHEMA private TO mcp_rls_helper;
ALTER FUNCTION private.current_tenant_id() OWNER TO mcp_rls_helper;
REVOKE CREATE ON SCHEMA private FROM mcp_rls_helper;

REVOKE ALL ON FUNCTION private.current_tenant_id() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.current_tenant_id() TO mcp_reader;
