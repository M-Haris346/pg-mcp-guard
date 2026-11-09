"""Load the demo dataset (schema shop), replacing whatever is there.

Usage: uv run python scripts/seed.py
Reads MIGRATOR_DATABASE_URL from the environment / .env.

All ids are deterministic (uuid5), so tests can import the constants below and
compute expected row counts from the same data the database holds.

People:
    alice    analyst at acme
    bob      admin at globex
    carol    analyst at acme AND admin at globex (tests switching tenant)
    mallory  member of nothing
Tenant initech has data but no members: nobody may ever see it.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, UUID, uuid5

import psycopg
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


def _id(name: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"https://pg-mcp-guard.invalid/seed/{name}")


ACME = _id("tenant/acme")
GLOBEX = _id("tenant/globex")
INITECH = _id("tenant/initech")
TENANTS: dict[UUID, str] = {ACME: "Acme Corp", GLOBEX: "Globex", INITECH: "Initech"}

ALICE = _id("user/alice")
BOB = _id("user/bob")
CAROL = _id("user/carol")
MALLORY = _id("user/mallory")
USERS: dict[UUID, tuple[str, str]] = {
    ALICE: ("alice@example.com", "Alice"),
    BOB: ("bob@example.com", "Bob"),
    CAROL: ("carol@example.com", "Carol"),
    MALLORY: ("mallory@example.com", "Mallory"),
}

MEMBERSHIPS: list[tuple[UUID, UUID, str]] = [
    (ACME, ALICE, "analyst"),
    (GLOBEX, BOB, "admin"),
    (ACME, CAROL, "analyst"),
    (GLOBEX, CAROL, "admin"),
]


@dataclass(frozen=True)
class Customer:
    id: UUID
    tenant_id: UUID
    name: str
    country: str
    email: str
    phone: str | None
    created_at: datetime


@dataclass(frozen=True)
class Product:
    id: UUID
    tenant_id: UUID
    name: str
    category: str
    price_cents: int


@dataclass(frozen=True)
class OrderItem:
    product_id: UUID
    qty: int
    unit_price_cents: int


@dataclass(frozen=True)
class Order:
    id: UUID
    tenant_id: UUID
    customer_id: UUID
    status: str
    created_at: datetime
    items: tuple[OrderItem, ...]

    @property
    def total_cents(self) -> int:
        return sum(i.qty * i.unit_price_cents for i in self.items)


_T0 = datetime(2026, 1, 5, 9, 0, tzinfo=UTC)

# (tenant, slug, customer names+countries, product name/category/price, orders)
# Orders: (customer index, status, [(product index, qty), ...])
_SPEC: list[
    tuple[
        UUID,
        str,
        list[tuple[str, str]],
        list[tuple[str, str, int]],
        list[tuple[int, str, list[tuple[int, int]]]],
    ]
] = [
    (
        ACME,
        "acme",
        [("Northwind Ltd", "GB"), ("Contoso GmbH", "DE"), ("Fabrikam Inc", "US")],
        [
            ("Anvil", "hardware", 4999),
            ("Rocket skates", "outdoor", 12999),
            ("Bird seed", "garden", 899),
        ],
        [
            (0, "paid", [(0, 2), (2, 5)]),
            (1, "shipped", [(1, 1)]),
            (2, "pending", [(2, 10)]),
            (0, "cancelled", [(1, 2), (0, 1)]),
        ],
    ),
    (
        GLOBEX,
        "globex",
        [("Tailspin Toys", "FR"), ("Wingtip Travel", "US"), ("Proseware", "PK")],
        [
            ("Hammock", "outdoor", 7999),
            ("Doomsday device", "hardware", 999999),
            ("Flamethrower", "garden", 34900),
        ],
        [
            (0, "paid", [(0, 1)]),
            (1, "paid", [(2, 2), (0, 3)]),
            (2, "shipped", [(1, 1)]),
        ],
    ),
    (
        INITECH,
        "initech",
        [("Penetrode", "US"), ("Chotchkie's", "US")],
        [("TPS cover sheet", "office", 99), ("Red stapler", "office", 1599)],
        [
            (0, "paid", [(0, 500)]),
            (1, "pending", [(1, 1)]),
        ],
    ),
]


def _build() -> tuple[list[Customer], list[Product], list[Order]]:
    customers: list[Customer] = []
    products: list[Product] = []
    orders: list[Order] = []
    for tenant_id, slug, cust_spec, prod_spec, order_spec in _SPEC:
        t_customers = [
            Customer(
                id=_id(f"{slug}/customer/{n}"),
                tenant_id=tenant_id,
                name=name,
                country=country,
                # Fake but realistic-looking PII: must never reach the model.
                email=f"contact{n}@{slug}-customer.example.com",
                phone=f"+1-555-01{n:02d}",
                created_at=_T0 + timedelta(days=n),
            )
            for n, (name, country) in enumerate(cust_spec)
        ]
        t_products = [
            Product(
                id=_id(f"{slug}/product/{n}"),
                tenant_id=tenant_id,
                name=name,
                category=category,
                price_cents=price,
            )
            for n, (name, category, price) in enumerate(prod_spec)
        ]
        t_orders = [
            Order(
                id=_id(f"{slug}/order/{n}"),
                tenant_id=tenant_id,
                customer_id=t_customers[cust_ix].id,
                status=status,
                created_at=_T0 + timedelta(days=10 + n),
                items=tuple(
                    OrderItem(t_products[p_ix].id, qty, t_products[p_ix].price_cents)
                    for p_ix, qty in lines
                ),
            )
            for n, (cust_ix, status, lines) in enumerate(order_spec)
        ]
        customers += t_customers
        products += t_products
        orders += t_orders
    return customers, products, orders


CUSTOMERS, PRODUCTS, ORDERS = _build()


def seed(database_url: str) -> None:
    """Replace all shop data with the dataset above, in one transaction."""
    with psycopg.connect(database_url) as conn, conn.cursor() as cur:
        cur.execute(
            "TRUNCATE shop.order_items, shop.orders, shop.products, shop.customers,"
            " shop.memberships, shop.users, shop.tenants"
        )
        cur.executemany(
            "INSERT INTO shop.tenants (id, name) VALUES (%s, %s)", list(TENANTS.items())
        )
        cur.executemany(
            "INSERT INTO shop.users (id, email, display_name) VALUES (%s, %s, %s)",
            [(uid, email, name) for uid, (email, name) in USERS.items()],
        )
        cur.executemany(
            "INSERT INTO shop.memberships (tenant_id, user_id, role) VALUES (%s, %s, %s)",
            MEMBERSHIPS,
        )
        cur.executemany(
            "INSERT INTO shop.customers"
            " (id, tenant_id, name, country, email, phone, created_at)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s)",
            [
                (c.id, c.tenant_id, c.name, c.country, c.email, c.phone, c.created_at)
                for c in CUSTOMERS
            ],
        )
        cur.executemany(
            "INSERT INTO shop.products (id, tenant_id, name, category, price_cents)"
            " VALUES (%s, %s, %s, %s, %s)",
            [(p.id, p.tenant_id, p.name, p.category, p.price_cents) for p in PRODUCTS],
        )
        cur.executemany(
            "INSERT INTO shop.orders (id, tenant_id, customer_id, status, total_cents, created_at)"
            " VALUES (%s, %s, %s, %s, %s, %s)",
            [
                (o.id, o.tenant_id, o.customer_id, o.status, o.total_cents, o.created_at)
                for o in ORDERS
            ],
        )
        cur.executemany(
            "INSERT INTO shop.order_items (order_id, tenant_id, product_id, qty, unit_price_cents)"
            " VALUES (%s, %s, %s, %s, %s)",
            [
                (o.id, o.tenant_id, i.product_id, i.qty, i.unit_price_cents)
                for o in ORDERS
                for i in o.items
            ],
        )


class SeedSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    migrator_database_url: SecretStr


def main() -> int:
    settings = SeedSettings()  # type: ignore[call-arg]
    seed(settings.migrator_database_url.get_secret_value())
    print(
        f"seeded {len(TENANTS)} tenants, {len(USERS)} users, {len(CUSTOMERS)} customers,"
        f" {len(PRODUCTS)} products, {len(ORDERS)} orders",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
