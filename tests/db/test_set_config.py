"""The reader cannot change settings (ADR 0002, Phase 6 gap check). Validator OFF.

set_config is the only way a SELECT can change a setting. It is revoked from
PUBLIC and granted back only to mcp_rls_helper, the owner of ctx.set_context,
which sets mcpguard.ctx (transaction-local) and nothing else.
"""

from __future__ import annotations

from typing import Any, LiteralString

import psycopg
import pytest
from psycopg import errors

from scripts.seed import ACME, ALICE, GLOBEX
from tests.db.helpers import TokenFactory, query_as

SET_CONFIG = "pg_catalog.set_config(text,text,boolean)"
ROLES = ["mcp_migrator", "mcp_rls_helper", "mcp_reader", "mcp_auditor"]

# (setting, value an attacker would want)
LIFTS = [
    ("statement_timeout", "0"),
    ("lock_timeout", "0"),
    ("idle_in_transaction_session_timeout", "0"),
    ("work_mem", "2GB"),
    ("hash_mem_multiplier", "1000"),
    ("search_path", "pg_catalog, public"),
    ("mcpguard.ctx", "v1.forged"),
]


def test_only_the_definer_owner_may_call_set_config(migrator: psycopg.Connection[Any]) -> None:
    rows = migrator.execute(
        "SELECT r, has_function_privilege(r, %s, 'EXECUTE') FROM unnest(%s::text[]) AS r",
        (SET_CONFIG, ROLES),
    ).fetchall()
    # mcp_rls_helper: owns ctx.set_context (SECURITY DEFINER). Nobody else:
    # no migration or script calls set_config as the migrator.
    assert dict(rows) == {
        "mcp_migrator": False,
        "mcp_rls_helper": True,
        "mcp_reader": False,
        "mcp_auditor": False,
    }


def test_reader_privilege_check_as_the_reader(reader: psycopg.Connection[Any]) -> None:
    # The same check the server runs at startup (reader_can_set_config).
    row = reader.execute(
        "SELECT has_function_privilege(current_user, %s, 'EXECUTE')", (SET_CONFIG,)
    ).fetchone()
    assert row == (False,)


@pytest.mark.attack
@pytest.mark.parametrize(("setting", "value"), LIFTS, ids=[name for name, _ in LIFTS])
@pytest.mark.parametrize("is_local", [False, True], ids=["session", "local"])
def test_reader_sql_cannot_change_its_own_settings(
    reader: psycopg.Connection[Any], setting: str, value: str, is_local: bool
) -> None:
    with (
        pytest.raises(
            errors.InsufficientPrivilege, match="permission denied for function set_config"
        ),
        reader.transaction(),
    ):
        reader.execute("SELECT set_config(%s, %s, %s)", (setting, value, is_local))


def test_set_cannot_be_smuggled_into_the_cursor(reader: psycopg.Connection[Any]) -> None:
    # The executor runs model SQL only as DECLARE ... CURSOR FOR <sql>, sent
    # with the extended protocol: a SET statement cannot get in either way.
    with pytest.raises(errors.SyntaxError), reader.transaction():
        reader.execute("DECLARE c CURSOR FOR SET statement_timeout = 0")
    with pytest.raises(errors.SyntaxError, match="cannot insert multiple commands"):
        reader.execute("SELECT 1; SET statement_timeout = 0", prepare=True)


def test_set_context_sets_only_the_context_and_only_for_the_transaction(
    reader: psycopg.Connection[Any], token: TokenFactory
) -> None:
    with reader.transaction():
        reader.execute("SELECT ctx.set_context(%s)", (token(ACME, ALICE),))
        row = reader.execute(
            "SELECT current_setting('mcpguard.ctx') <> '', current_setting('statement_timeout'),"
            " current_setting('search_path'), ctx.current_tenant_id()"
        ).fetchone()
    assert row == (True, "5s", "shop", ACME)  # other settings untouched

    after = reader.execute("SELECT coalesce(current_setting('mcpguard.ctx', true), '')").fetchone()
    assert after == ("",)  # transaction-local


def test_forged_token_via_set_context_sees_nothing(
    reader: psycopg.Connection[Any], token: TokenFactory
) -> None:
    valid = token(ACME, ALICE)
    tenant_swapped = valid.replace(str(ACME), str(GLOBEX))
    assert query_as(reader, valid, "SELECT DISTINCT tenant_id FROM orders") == [(ACME,)]
    assert query_as(reader, tenant_swapped, "SELECT tenant_id FROM orders") == []


def test_reader_reaches_ctx_but_not_private(migrator: psycopg.Connection[Any]) -> None:
    row = migrator.execute(
        "SELECT has_schema_privilege('mcp_reader', 'ctx', 'USAGE'),"
        " has_schema_privilege('mcp_reader', 'private', 'USAGE'),"
        " has_schema_privilege('mcp_reader', 'ctx', 'CREATE'),"
        " to_regprocedure('private.current_tenant_id()') IS NULL"
    ).fetchone()
    assert row == (True, False, False, True)


def test_ctx_functions_are_definer_owned_and_executable_by_the_reader_only(
    migrator: psycopg.Connection[Any],
) -> None:
    rows = migrator.execute(
        """
        SELECT p.oid::regprocedure::text, pg_get_userbyid(p.proowner), p.prosecdef,
               (SELECT array_agg(CASE WHEN a.grantee = 0 THEN 'PUBLIC'
                                      ELSE pg_get_userbyid(a.grantee) END)
                  FROM aclexplode(p.proacl) AS a WHERE a.privilege_type = 'EXECUTE')
          FROM pg_proc p WHERE p.pronamespace = 'ctx'::regnamespace ORDER BY 1
        """
    ).fetchall()
    assert [
        (name, owner, definer, sorted(grantees)) for name, owner, definer, grantees in rows
    ] == [
        ("ctx.current_tenant_id()", "mcp_rls_helper", True, ["mcp_reader", "mcp_rls_helper"]),
        ("ctx.set_context(text)", "mcp_rls_helper", True, ["mcp_reader", "mcp_rls_helper"]),
    ]  # no PUBLIC: 002's revoke never took effect; 007 fixed it


@pytest.mark.parametrize("role_url", ["auditor", "migrator"])
def test_other_roles_cannot_set_the_context(request: pytest.FixtureRequest, role_url: str) -> None:
    conn: psycopg.Connection[Any] = request.getfixturevalue(role_url)
    sql: LiteralString = "SELECT ctx.set_context('x')"
    with pytest.raises(errors.InsufficientPrivilege), conn.transaction():
        conn.execute(sql)
