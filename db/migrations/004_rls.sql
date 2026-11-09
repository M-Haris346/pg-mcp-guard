-- Row-level security on every table in shop (rule 3).
-- FORCE also applies RLS to the table owner; the migrator still sees all rows
-- because it has BYPASSRLS, which is deliberate (migrations and seed).

ALTER TABLE shop.tenants     ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
ALTER TABLE shop.users       ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
ALTER TABLE shop.memberships ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
ALTER TABLE shop.customers   ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
ALTER TABLE shop.products    ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
ALTER TABLE shop.orders      ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
ALTER TABLE shop.order_items ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;

-- shop.users and shop.memberships get no policy for mcp_reader: deny by default
-- (and the reader has no grant on them either).

-- (SELECT private.current_tenant_id()) is wrapped in a sub-select so the
-- planner evaluates it once per query (an InitPlan), not once per row.
CREATE POLICY tenant_read ON shop.tenants
    FOR SELECT TO mcp_reader
    USING (id = (SELECT private.current_tenant_id()));

CREATE POLICY tenant_read ON shop.customers
    FOR SELECT TO mcp_reader
    USING (tenant_id = (SELECT private.current_tenant_id()));

CREATE POLICY tenant_read ON shop.products
    FOR SELECT TO mcp_reader
    USING (tenant_id = (SELECT private.current_tenant_id()));

CREATE POLICY tenant_read ON shop.orders
    FOR SELECT TO mcp_reader
    USING (tenant_id = (SELECT private.current_tenant_id()));

CREATE POLICY tenant_read ON shop.order_items
    FOR SELECT TO mcp_reader
    USING (tenant_id = (SELECT private.current_tenant_id()));
