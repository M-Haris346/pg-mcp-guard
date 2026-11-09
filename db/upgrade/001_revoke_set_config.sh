#!/usr/bin/env bash
# Upgrade for databases bootstrapped before the set_config revoke (Phase 6).
#
# New databases get this from db/bootstrap/00_bootstrap.sh. Existing ones
# (created before that change) need it applied once, as the superuser.
# Idempotent: safe to run any number of times. Prints the resulting
# privileges per role, and fails if mcp_reader can still call set_config.
#
# docker compose:
#   docker compose exec -T db bash -s < db/upgrade/001_revoke_set_config.sh
# elsewhere (PGHOST / PGUSER / PGPASSWORD for a superuser):
#   bash db/upgrade/001_revoke_set_config.sh
set -euo pipefail

UPGRADE_PSQL=(psql -v ON_ERROR_STOP=1 --no-psqlrc --quiet
    --username "${PGUSER:-${POSTGRES_USER:-postgres}}")

for db in mcpguard mcpguard_test; do
    exists=$("${UPGRADE_PSQL[@]}" --dbname postgres -tAc \
        "SELECT 1 FROM pg_database WHERE datname = '$db'")
    if [ "$exists" != "1" ]; then
        echo "$db: not present, skipped"
        continue
    fi
    "${UPGRADE_PSQL[@]}" --dbname "$db" <<'SQL'
REVOKE EXECUTE ON FUNCTION pg_catalog.set_config(text, text, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pg_catalog.set_config(text, text, boolean) TO mcp_rls_helper;
SQL
    "${UPGRADE_PSQL[@]}" --dbname "$db" -tA <<'SQL'
SELECT current_database() || ': set_config EXECUTE -> '
       || string_agg(r || '=' || has_function_privilege(r, 'pg_catalog.set_config(text,text,boolean)', 'EXECUTE'), ', ' ORDER BY r)
  FROM unnest(ARRAY['mcp_migrator', 'mcp_rls_helper', 'mcp_reader', 'mcp_auditor']) AS r;
DO $$
BEGIN
    IF has_function_privilege('mcp_reader', 'pg_catalog.set_config(text,text,boolean)', 'EXECUTE') THEN
        RAISE EXCEPTION 'mcp_reader can still execute set_config';  -- the revoke did not take
    END IF;
END $$;
SQL
done
