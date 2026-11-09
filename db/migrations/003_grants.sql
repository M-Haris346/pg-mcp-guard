-- mcp_reader: SELECT only, on the allowlisted tables and columns.
-- Not granted at all: shop.users, shop.memberships, private.context_key, audit.*.

-- USAGE on private only so RLS policies can call the helper (policy
-- expressions run with the querying role's privileges). The reader has no
-- privilege on any table in private.
GRANT USAGE ON SCHEMA shop, private TO mcp_reader;

GRANT SELECT (id, name) ON shop.tenants TO mcp_reader;
-- Column-level grant: email and phone are never readable by the model.
GRANT SELECT (id, tenant_id, name, country, created_at) ON shop.customers TO mcp_reader;
GRANT SELECT ON shop.products, shop.orders, shop.order_items TO mcp_reader;
GRANT SELECT ON shop.order_summary TO mcp_reader;
