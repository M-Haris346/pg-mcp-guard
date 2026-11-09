-- Schemas and tables. Runs as mcp_migrator, which owns everything created here.

CREATE SCHEMA shop;      -- the only schema exposed to the model
CREATE SCHEMA private;   -- context key + RLS helper; never exposed
CREATE SCHEMA audit;     -- tool-call log; written by mcp_auditor only

CREATE TABLE shop.tenants (
    id   uuid PRIMARY KEY,
    name text NOT NULL
);

CREATE TABLE shop.users (
    id           uuid PRIMARY KEY,
    email        ext.citext NOT NULL UNIQUE,
    display_name text NOT NULL
);

CREATE TABLE shop.memberships (
    tenant_id uuid NOT NULL REFERENCES shop.tenants (id),
    user_id   uuid NOT NULL REFERENCES shop.users (id),
    role      text NOT NULL CHECK (role IN ('analyst', 'admin')),
    PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE shop.customers (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES shop.tenants (id),
    name       text NOT NULL,
    country    text NOT NULL,
    email      text NOT NULL,   -- sensitive: never granted to mcp_reader
    phone      text,            -- sensitive: never granted to mcp_reader
    created_at timestamptz NOT NULL,
    UNIQUE (id, tenant_id)
);

CREATE TABLE shop.products (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES shop.tenants (id),
    name        text NOT NULL,
    category    text NOT NULL,
    price_cents integer NOT NULL CHECK (price_cents >= 0),
    UNIQUE (id, tenant_id)
);

-- Composite foreign keys (id, tenant_id) make a cross-tenant reference
-- impossible: an order can only point at a customer of the same tenant, an
-- order item only at an order and a product of the same tenant.
CREATE TABLE shop.orders (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES shop.tenants (id),
    customer_id uuid NOT NULL,
    status      text NOT NULL CHECK (status IN ('pending', 'paid', 'shipped', 'cancelled')),
    total_cents integer NOT NULL CHECK (total_cents >= 0),
    created_at  timestamptz NOT NULL,
    UNIQUE (id, tenant_id),
    FOREIGN KEY (customer_id, tenant_id) REFERENCES shop.customers (id, tenant_id)
);

CREATE TABLE shop.order_items (
    order_id         uuid NOT NULL,
    tenant_id        uuid NOT NULL,
    product_id       uuid NOT NULL,
    qty              integer NOT NULL CHECK (qty > 0),
    unit_price_cents integer NOT NULL CHECK (unit_price_cents >= 0),
    PRIMARY KEY (order_id, product_id),
    FOREIGN KEY (order_id, tenant_id) REFERENCES shop.orders (id, tenant_id),
    FOREIGN KEY (product_id, tenant_id) REFERENCES shop.products (id, tenant_id)
);

-- Exactly one row (the boolean primary key can only be true).
CREATE TABLE private.context_key (
    id  boolean PRIMARY KEY DEFAULT true CHECK (id),
    key bytea NOT NULL CHECK (octet_length(key) >= 32)
);

-- security_invoker: the view runs with the querying role's privileges and RLS.
-- A default view runs as its owner (mcp_migrator, BYPASSRLS) and would return
-- every tenant's rows. Rule 8; asserted for every view by tests/db/test_rls.py.
CREATE VIEW shop.order_summary WITH (security_invoker = true) AS
SELECT
    o.id          AS order_id,
    o.tenant_id,
    c.name        AS customer_name,
    o.status,
    o.total_cents,
    o.created_at,
    (SELECT count(*)
       FROM shop.order_items i
      WHERE i.order_id = o.id AND i.tenant_id = o.tenant_id) AS item_count
FROM shop.orders o
JOIN shop.customers c ON c.id = o.customer_id AND c.tenant_id = o.tenant_id;
