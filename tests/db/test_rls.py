"""Tenant isolation, the signed context (rule 4), and views (rule 8). Validator OFF."""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any, LiteralString
from uuid import UUID

import psycopg
import pytest

from scripts.seed import (
    ACME,
    ALICE,
    BOB,
    CAROL,
    CUSTOMERS,
    GLOBEX,
    INITECH,
    MALLORY,
    ORDERS,
    PRODUCTS,
)
from tests.db.helpers import TokenFactory, query_as

# Every relation mcp_reader can SELECT, with a query that returns tenant ids.
EXPOSED: dict[str, LiteralString] = {
    "tenants": "SELECT id FROM shop.tenants",
    "customers": "SELECT tenant_id FROM shop.customers",
    "products": "SELECT tenant_id FROM shop.products",
    "orders": "SELECT tenant_id FROM shop.orders",
    "order_items": "SELECT tenant_id FROM shop.order_items",
    "order_summary": "SELECT tenant_id FROM shop.order_summary",
}


def _expected_count(relation: str, tenant: UUID) -> int:
    counts = {
        "tenants": 1,
        "customers": sum(c.tenant_id == tenant for c in CUSTOMERS),
        "products": sum(p.tenant_id == tenant for p in PRODUCTS),
        "orders": sum(o.tenant_id == tenant for o in ORDERS),
        "order_items": sum(len(o.items) for o in ORDERS if o.tenant_id == tenant),
        "order_summary": sum(o.tenant_id == tenant for o in ORDERS),
    }
    return counts[relation]


def _raw_token(payload: str, key: bytes) -> str:
    """Sign an arbitrary payload, bypassing sign_context's checks."""
    return f"{payload}.{hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()}"


# --- tenant isolation -----------------------------------------------------


@pytest.mark.parametrize("relation", EXPOSED)
@pytest.mark.parametrize(
    ("tenant", "user"),
    [(ACME, ALICE), (GLOBEX, BOB), (ACME, CAROL), (GLOBEX, CAROL)],
    ids=["alice@acme", "bob@globex", "carol@acme", "carol@globex"],
)
def test_member_sees_exactly_their_tenant(
    reader: psycopg.Connection[Any], token: TokenFactory, relation: str, tenant: UUID, user: UUID
) -> None:
    rows = query_as(reader, token(tenant, user), EXPOSED[relation])

    assert {r[0] for r in rows} == {tenant}
    assert len(rows) == _expected_count(relation, tenant)


@pytest.mark.parametrize("relation", EXPOSED)
@pytest.mark.parametrize(
    ("tenant", "user"),
    [(GLOBEX, ALICE), (ACME, BOB), (ACME, MALLORY), (INITECH, CAROL)],
    ids=["alice@globex", "bob@acme", "mallory@acme", "carol@initech"],
)
def test_validly_signed_but_not_a_member_sees_nothing(
    reader: psycopg.Connection[Any], token: TokenFactory, relation: str, tenant: UUID, user: UUID
) -> None:
    # The signature is valid (the key holder signed it), but membership fails.
    assert query_as(reader, token(tenant, user), EXPOSED[relation]) == []


@pytest.mark.parametrize("relation", EXPOSED)
def test_no_context_sees_nothing(reader: psycopg.Connection[Any], relation: str) -> None:
    assert query_as(reader, None, EXPOSED[relation]) == []


def test_context_is_transaction_local(reader: psycopg.Connection[Any], token: TokenFactory) -> None:
    with reader.transaction():
        reader.execute("SELECT set_config('mcpguard.ctx', %s, true)", (token(ACME, ALICE),))
        assert reader.execute("SELECT count(*) FROM shop.orders").fetchone() != (0,)

    # Same connection, next transaction: the context is gone.
    assert query_as(reader, None, "SELECT id FROM shop.orders") == []


# --- forged / malformed context (validator OFF) ----------------------------


def _forgeries(key: bytes) -> dict[str, str]:
    now = int(time.time())
    good_payload = f"v1.{ACME}.{ALICE}.{now + 60}"
    good = _raw_token(good_payload, key)
    good_sig = good.rsplit(".", 1)[1]
    wrong_key = b"x" * 32
    return {
        "unsigned": good_payload,
        "zero_signature": f"{good_payload}.{'0' * 64}",
        "wrong_key": _raw_token(good_payload, wrong_key),
        "tenant_swapped_keeping_sig": f"v1.{GLOBEX}.{ALICE}.{now + 60}.{good_sig}",
        "user_swapped_keeping_sig": f"v1.{ACME}.{CAROL}.{now + 60}.{good_sig}",
        "exp_extended_keeping_sig": f"v1.{ACME}.{ALICE}.{now + 120}.{good_sig}",
        "expired": _raw_token(f"v1.{ACME}.{ALICE}.{now - 1}", key),
        "exp_beyond_max_ttl": _raw_token(f"v1.{ACME}.{ALICE}.{now + 3600}", key),
        "version_v2": _raw_token(f"v2.{ACME}.{ALICE}.{now + 60}", key),
        "uppercase_uuid": _raw_token(f"v1.{str(ACME).upper()}.{ALICE}.{now + 60}", key),
        "extra_part": f"{good}.extra",
        "missing_part": _raw_token(f"v1.{ACME}.{now + 60}", key),
        "not_a_uuid": _raw_token(f"v1.acme.{ALICE}.{now + 60}", key),
        "negative_exp": _raw_token(f"v1.{ACME}.{ALICE}.-5", key),
        "sql_in_token": f"v1.{ACME}.{ALICE}.{now + 60}.'; DROP TABLE shop.orders; --",
        "garbage": "not a token at all",
        "empty": "",
        "very_long": "v1." + "a" * 10_000,
    }


FORGERY_NAMES = list(_forgeries(b"k" * 32))


@pytest.mark.attack
@pytest.mark.parametrize("forgery", FORGERY_NAMES)
@pytest.mark.parametrize("relation", ["tenants", "orders", "order_summary"])
def test_forged_context_sees_nothing_and_does_not_error(
    reader: psycopg.Connection[Any], context_key: bytes, forgery: str, relation: str
) -> None:
    # This is the attack rule 4 exists for: model-written SQL calling
    # set_config('mcpguard.ctx', ...) itself. query_as does exactly that,
    # as mcp_reader, with no validator in the way.
    forged = _forgeries(context_key)[forgery]
    assert query_as(reader, forged, EXPOSED[relation]) == []


@pytest.mark.attack
def test_reader_can_replay_its_own_valid_token_only_for_its_tenant(
    reader: psycopg.Connection[Any], token: TokenFactory
) -> None:
    # Allowed counterpart: a valid token set by the reader's own SQL works,
    # but grants nothing beyond the principal it was issued for (ADR 0002).
    rows = query_as(reader, token(ACME, ALICE), "SELECT DISTINCT tenant_id FROM shop.orders")
    assert rows == [(ACME,)]


# --- coverage checks over the catalog -------------------------------------


def _tables_missing_forced_rls(conn: psycopg.Connection[Any]) -> list[str]:
    rows = conn.execute(
        """
        SELECT c.relname
          FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'shop' AND c.relkind IN ('r', 'p')
           AND NOT (c.relrowsecurity AND c.relforcerowsecurity)
         ORDER BY 1
        """
    ).fetchall()
    return [r[0] for r in rows]


def _views_without_security_invoker(conn: psycopg.Connection[Any]) -> list[str]:
    # Materialized views ('m') are always flagged: they store the owner's view
    # of the data and cannot be security_invoker.
    rows = conn.execute(
        """
        SELECT c.relname
          FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'shop' AND c.relkind IN ('v', 'm')
           AND NOT (c.relkind = 'v' AND EXISTS (
                 SELECT 1 FROM unnest(coalesce(c.reloptions, '{}')) AS opt
                  WHERE opt ~* '^security_invoker=(true|on|yes|1)$'))
         ORDER BY 1
        """
    ).fetchall()
    return [r[0] for r in rows]


def test_every_shop_table_has_enabled_and_forced_rls(migrator: psycopg.Connection[Any]) -> None:
    assert _tables_missing_forced_rls(migrator) == []


def test_every_shop_view_is_security_invoker(migrator: psycopg.Connection[Any]) -> None:
    views = migrator.execute("SELECT count(*) FROM pg_views WHERE schemaname = 'shop'").fetchone()
    assert views is not None and views[0] >= 1  # the check is not vacuous
    assert _views_without_security_invoker(migrator) == []


@pytest.mark.attack
def test_default_view_would_bypass_rls_and_the_check_catches_it(
    migrator: psycopg.Connection[Any], reader: psycopg.Connection[Any], token: TokenFactory
) -> None:
    """Why rule 8 exists: a default view runs as its owner, not the caller."""
    migrator.execute("CREATE VIEW shop.zz_leaky_orders AS SELECT id, tenant_id FROM shop.orders")
    try:
        migrator.execute("GRANT SELECT ON shop.zz_leaky_orders TO mcp_reader")

        rows = query_as(reader, token(ACME, ALICE), "SELECT tenant_id FROM shop.zz_leaky_orders")
        assert {r[0] for r in rows} == {ACME, GLOBEX, INITECH}  # leak: every tenant
        assert "zz_leaky_orders" in _views_without_security_invoker(migrator)
    finally:
        migrator.execute("DROP VIEW shop.zz_leaky_orders")
