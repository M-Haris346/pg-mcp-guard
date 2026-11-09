"""The validator's allowlists must agree with the real database.

The validator matches names; these tests check what those names resolve to in
Postgres 18, as the roles that actually run queries.
"""

from __future__ import annotations

from typing import Any, LiteralString, cast

import psycopg
import pytest
from psycopg import errors

from app.validator import DEFAULT_POLICY
from scripts.seed import ACME, ALICE
from tests.db.helpers import TokenFactory
from tests.validator.corpus import Case, load_corpus

ALLOWED_CASES = [c for c in load_corpus() if c.verdict == "allow"]


def test_relation_allowlist_equals_reader_grants(migrator: psycopg.Connection[Any]) -> None:
    rows = migrator.execute(
        """
        SELECT c.relname
          FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = %s AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
           AND has_any_column_privilege('mcp_reader', c.oid, 'SELECT')
        """,
        (DEFAULT_POLICY.schema,),
    ).fetchall()
    assert {r[0] for r in rows} == DEFAULT_POLICY.relations


def test_no_allowlisted_relation_name_exists_in_pg_catalog(
    migrator: psycopg.Connection[Any],
) -> None:
    # pg_catalog is searched before shop; a same-named catalog relation would
    # win for unqualified references.
    rows = migrator.execute(
        "SELECT relname FROM pg_class"
        " WHERE relnamespace = 'pg_catalog'::regnamespace AND relname = ANY(%s)",
        (sorted(DEFAULT_POLICY.relations),),
    ).fetchall()
    assert rows == []


@pytest.mark.parametrize("name", sorted(DEFAULT_POLICY.functions))
def test_allowlisted_function_is_safe_in_every_overload(
    migrator: psycopg.Connection[Any], name: str
) -> None:
    rows = migrator.execute(
        "SELECT p.oid::regprocedure::text, n.nspname, p.provolatile, p.prosecdef,"
        "       has_schema_privilege('mcp_reader', n.oid, 'USAGE')"
        " FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace"
        " WHERE p.proname = %s",
        (name,),
    ).fetchall()
    assert any(schema == "pg_catalog" for _, schema, *_ in rows), f"{name} not in pg_catalog"
    for signature, schema, volatility, security_definer, reader_can_use in rows:
        if schema != "pg_catalog":
            # e.g. citext's ext.max(citext): the validator only allows
            # unqualified or pg_catalog-qualified names, so an overload elsewhere
            # is reachable only if the reader can use that schema.
            assert not reader_can_use, f"{signature} is reachable by mcp_reader"
            continue
        assert volatility != "v", f"{signature} is VOLATILE (may have side effects)"
        assert not security_definer, f"{signature} is SECURITY DEFINER"


def test_allowlisted_types_exist_in_pg_catalog(migrator: psycopg.Connection[Any]) -> None:
    rows = migrator.execute(
        "SELECT typname FROM pg_type"
        " WHERE typnamespace = 'pg_catalog'::regnamespace AND typname = ANY(%s)",
        (sorted(DEFAULT_POLICY.types),),
    ).fetchall()
    assert {r[0] for r in rows} == DEFAULT_POLICY.types


def test_allowlisted_operators_exist_in_pg_catalog(migrator: psycopg.Connection[Any]) -> None:
    rows = migrator.execute(
        "SELECT DISTINCT oprname FROM pg_operator"
        " WHERE oprnamespace = 'pg_catalog'::regnamespace AND oprname = ANY(%s)",
        (sorted(DEFAULT_POLICY.operators),),
    ).fetchall()
    assert {r[0] for r in rows} == DEFAULT_POLICY.operators


@pytest.mark.parametrize(
    ("what", "sql"),
    [
        (
            "functions",
            "SELECT p.oid::regprocedure::text FROM pg_proc p"
            " WHERE p.pronamespace = 'shop'::regnamespace",
        ),
        (
            "operators",
            "SELECT oprname FROM pg_operator WHERE oprnamespace = 'shop'::regnamespace",
        ),
        (
            # Every table and view has a composite row type (and its array
            # type); those are part of the relation, not something to shadow
            # with, and the validator never allows them as cast targets.
            "types",
            "SELECT t.typname FROM pg_type t"
            " WHERE t.typnamespace = 'shop'::regnamespace AND t.typtype <> 'c'"
            " AND NOT EXISTS (SELECT 1 FROM pg_type e WHERE e.oid = t.typelem AND e.typtype = 'c')",
        ),
    ],
)
def test_nothing_in_shop_can_shadow_builtins(
    migrator: psycopg.Connection[Any], what: str, sql: LiteralString
) -> None:
    # If shop ever held functions, operators or types, a search_path that put
    # shop before pg_catalog would let them shadow the allowlisted built-ins.
    assert migrator.execute(sql).fetchall() == [], f"unexpected {what} in schema shop"


@pytest.mark.parametrize("case", ALLOWED_CASES, ids=[c.id for c in ALLOWED_CASES])
def test_allowed_corpus_entry_runs_as_reader(
    reader: psycopg.Connection[Any], token: TokenFactory, case: Case
) -> None:
    """Every query the validator allows is real SQL the server accepts, run the
    way the executor will run it (extended protocol, valid context). Entries
    marked enforced_by = "db" must be refused by the database instead."""
    sql = cast(LiteralString, case.sql)  # corpus files are part of this repo
    with reader.transaction():
        reader.execute("SELECT ctx.set_context(%s)", (token(ACME, ALICE),))
        if case.enforced_by == "db":
            with pytest.raises(errors.InsufficientPrivilege), reader.transaction():
                reader.execute(sql, prepare=True)
        else:
            reader.execute(sql, prepare=True).fetchall()
