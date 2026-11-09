"""Grants, read-only, role posture and session-isolation tests as mcp_reader. Validator OFF."""

from __future__ import annotations

import threading
import time
from typing import Any, LiteralString

import psycopg
import pytest
from psycopg import errors

from scripts.seed import ACME, ALICE
from tests.db.helpers import TokenFactory, query_as

# --- column grants ----------------------------------------------------------


def test_granted_customer_columns_are_readable(
    reader: psycopg.Connection[Any], token: TokenFactory
) -> None:
    rows = query_as(
        reader, token(ACME, ALICE), "SELECT id, tenant_id, name, country, created_at FROM customers"
    )
    assert rows  # search_path = shop comes from the role setting


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT email FROM shop.customers",
        "SELECT phone FROM shop.customers",
        "SELECT * FROM shop.customers",
        "SELECT count(email) FROM shop.customers",
        "SELECT name FROM shop.customers WHERE email LIKE '%@%'",  # also via WHERE
    ],
)
def test_sensitive_customer_columns_are_denied(
    reader: psycopg.Connection[Any], token: TokenFactory, sql: LiteralString
) -> None:
    with pytest.raises(errors.InsufficientPrivilege, match="permission denied for table customers"):
        query_as(reader, token(ACME, ALICE), sql)


# --- objects the reader must not touch -----------------------------------


@pytest.mark.parametrize(
    ("sql", "message"),
    [
        ("SELECT * FROM shop.users", "permission denied for table users"),
        ("SELECT * FROM shop.memberships", "permission denied for table memberships"),
        ("SELECT * FROM private.context_key", "permission denied for table context_key"),
        ("SELECT * FROM audit.tool_calls", "permission denied for schema audit"),
        ("SELECT ext.hmac('a', 'b', 'sha256')", "permission denied for schema ext"),
    ],
)
def test_hidden_objects_are_denied(
    reader: psycopg.Connection[Any], sql: LiteralString, message: str
) -> None:
    with pytest.raises(errors.InsufficientPrivilege, match=message):
        query_as(reader, None, sql)


def test_reader_can_call_the_context_helper(reader: psycopg.Connection[Any]) -> None:
    # Policies run with the reader's privileges, so it must be able to call
    # the helper. Without a context it just returns NULL.
    assert query_as(reader, None, "SELECT private.current_tenant_id()") == [(None,)]


# --- writes: two independent layers ----------------------------------------

WRITES: list[LiteralString] = [
    "INSERT INTO shop.tenants (id, name) VALUES (gen_random_uuid(), 'x')",
    "UPDATE shop.orders SET status = 'paid'",
    "DELETE FROM shop.order_items",
    "TRUNCATE shop.orders",
]


def test_default_transaction_is_read_only(reader: psycopg.Connection[Any]) -> None:
    assert query_as(reader, None, "SHOW transaction_read_only") == [("on",)]


@pytest.mark.parametrize("sql", WRITES)
def test_writes_fail_in_the_default_read_only_transaction(
    reader: psycopg.Connection[Any], sql: LiteralString
) -> None:
    with pytest.raises(errors.ReadOnlySqlTransaction):
        query_as(reader, None, sql)


@pytest.mark.parametrize(
    "sql",
    [
        *WRITES,
        "CREATE TABLE shop.x (id int)",
        "CREATE TABLE public.x (id int)",
        "CREATE TEMP TABLE x (id int)",
        "CREATE FUNCTION shop.f() RETURNS int LANGUAGE sql AS 'SELECT 1'",
        "SELECT lo_create(0)",
        "SELECT lo_from_bytea(0, 'x')",
        "ALTER TABLE shop.orders DISABLE ROW LEVEL SECURITY",
        "DROP POLICY tenant_read ON shop.orders",
    ],
)
def test_writes_still_fail_on_privileges_in_a_read_write_transaction(
    reader: psycopg.Connection[Any], sql: LiteralString
) -> None:
    # Layer 2: even if read-only is switched off, the reader owns nothing and
    # holds no write privilege.
    with pytest.raises(errors.InsufficientPrivilege), reader.transaction():
        reader.execute("SET TRANSACTION READ WRITE")
        reader.execute(sql)


# --- the Datadog case: multi-statement escape -------------------------------


def test_extended_protocol_refuses_multiple_statements(reader: psycopg.Connection[Any]) -> None:
    """Driver layer: with parameters or prepare=True, psycopg uses the extended
    protocol, and Postgres refuses more than one statement. The Phase 3 executor
    must always run model SQL this way."""
    with pytest.raises(errors.SyntaxError, match="cannot insert multiple commands"):
        reader.execute("SELECT 1; SELECT 2", prepare=True)


@pytest.mark.parametrize(
    "attack",
    [
        "COMMIT; DROP TABLE shop.orders",
        "COMMIT; BEGIN READ WRITE; DROP TABLE shop.orders",
        "COMMIT; SET default_transaction_read_only = off; DROP TABLE shop.orders",
    ],
)
def test_commit_escape_cannot_drop_a_table(
    reader: psycopg.Connection[Any], migrator: psycopg.Connection[Any], attack: LiteralString
) -> None:
    # Simple query protocol (no parameters) *does* run multiple statements:
    # this is the path the archived reference server exposed. The database
    # must hold anyway.
    with pytest.raises((errors.ReadOnlySqlTransaction, errors.InsufficientPrivilege)):
        reader.execute(attack)

    assert migrator.execute("SELECT to_regclass('shop.orders')").fetchone() == ("shop.orders",)


# --- role posture -----------------------------------------------------------


def test_reader_role_attributes(migrator: psycopg.Connection[Any]) -> None:
    row = migrator.execute(
        "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication, rolconnlimit"
        " FROM pg_roles WHERE rolname = 'mcp_reader'"
    ).fetchone()
    assert row == (False, False, False, False, False, 10)


def test_reader_owns_nothing(migrator: psycopg.Connection[Any]) -> None:
    row = migrator.execute(
        """
        SELECT (SELECT count(*) FROM pg_class     WHERE relowner = r.oid)
             + (SELECT count(*) FROM pg_proc      WHERE proowner = r.oid)
             + (SELECT count(*) FROM pg_namespace WHERE nspowner = r.oid)
             + (SELECT count(*) FROM pg_type      WHERE typowner = r.oid)
          FROM pg_roles r WHERE r.rolname = 'mcp_reader'
        """
    ).fetchone()
    assert row == (0,)


@pytest.mark.parametrize(
    ("setting", "expected"),
    [
        ("default_transaction_read_only", "on"),
        ("statement_timeout", "5s"),
        ("lock_timeout", "1s"),
        ("idle_in_transaction_session_timeout", "10s"),
        ("temp_file_limit", "64MB"),
        ("search_path", "shop"),
    ],
)
def test_role_level_settings_apply_to_new_sessions(
    reader: psycopg.Connection[Any], setting: str, expected: str
) -> None:
    row = reader.execute("SELECT current_setting(%s)", (setting,)).fetchone()
    assert row == (expected,)


def test_reader_cannot_raise_temp_file_limit(reader: psycopg.Connection[Any]) -> None:
    with pytest.raises(errors.InsufficientPrivilege, match="temp_file_limit"):
        reader.execute("SET temp_file_limit = -1")
    with pytest.raises(errors.InsufficientPrivilege, match="temp_file_limit"):
        reader.execute("SELECT set_config('temp_file_limit', '-1', false)")


# --- session isolation: pg_stat_activity --------------------------------------

MARKER = "marker_7f3a_other_session"


@pytest.mark.parametrize(
    "spy_sql",
    [
        "SELECT query FROM pg_stat_activity",
        "SELECT query FROM pg_catalog.pg_stat_get_activity(NULL)",
        "SELECT pg_catalog.pg_stat_get_backend_activity(b)"
        " FROM pg_catalog.pg_stat_get_backend_idset() AS b",
    ],
)
def test_reader_cannot_see_another_reader_sessions_query_or_token(
    reader_url: str, token: TokenFactory, spy_sql: LiteralString
) -> None:
    """All principals share the mcp_reader role, and Postgres shows a role the
    query text of its own other sessions. The bootstrap revokes that."""
    ctx = token(ACME, ALICE)
    with (
        psycopg.connect(reader_url, autocommit=True) as victim,
        psycopg.connect(reader_url, autocommit=True) as spy,
    ):
        # Victim: idle in transaction, last query contains the marker; its
        # context token was sent as a bind parameter.
        victim.execute("BEGIN")
        victim.execute("SELECT set_config('mcpguard.ctx', %s, true)", (ctx,))
        victim.execute(f"SELECT '{MARKER}'")  # noqa: S608 - constant test marker

        try:
            rows = spy.execute(spy_sql).fetchall()
        except errors.InsufficientPrivilege:
            rows = []
        finally:
            victim.execute("ROLLBACK")

    seen = " ".join(str(r[0]) for r in rows)
    assert MARKER not in seen
    assert ctx not in seen
    assert ctx.rsplit(".", 1)[1] not in seen  # not even the signature


@pytest.mark.parametrize(
    "spy_sql",
    [
        "SELECT query FROM pg_stat_activity",
        "SELECT query FROM pg_catalog.pg_stat_get_activity(NULL)",
        "SELECT pg_catalog.pg_stat_get_backend_activity(1)",
        "SELECT pg_catalog.pg_stat_get_backend_idset()",
        "SELECT pg_catalog.pg_stat_get_backend_pid(1)",
    ],
)
def test_activity_views_are_denied_outright(
    reader: psycopg.Connection[Any], spy_sql: LiteralString
) -> None:
    with pytest.raises(errors.InsufficientPrivilege):
        reader.execute(spy_sql)


# --- session isolation: cancel / terminate ----------------------------------


def _pid(conn: psycopg.Connection[Any]) -> int:
    row = conn.execute("SELECT pg_backend_pid()").fetchone()
    assert row is not None
    return int(row[0])


def _attempt(conn: psycopg.Connection[Any], sql: LiteralString, pid: int) -> Exception | None:
    """Run the attack; return the error it raised, or None if it was allowed."""
    try:
        conn.execute(sql, (pid,))
    except errors.InsufficientPrivilege as exc:
        return exc
    return None


def test_reader_cannot_cancel_another_reader_sessions_query(reader_url: str) -> None:
    """All principals share mcp_reader, and by default a role may cancel its own
    other backends. The bootstrap revokes pg_cancel_backend from PUBLIC."""
    with (
        psycopg.connect(reader_url, autocommit=True) as attacker,
        psycopg.connect(reader_url, autocommit=True) as victim,
    ):
        # The attacker is handed the pid directly: pids are small integers and
        # guessable, so the test must not rely on hiding them.
        victim_pid = _pid(victim)
        victim_errors: list[BaseException] = []

        def victim_query() -> None:
            try:
                victim.execute("SELECT pg_sleep(1.5)")
            except BaseException as exc:  # recorded and asserted below
                victim_errors.append(exc)

        worker = threading.Thread(target=victim_query)
        worker.start()
        try:
            time.sleep(0.3)  # let the victim's query start
            attack_error = _attempt(attacker, "SELECT pg_cancel_backend(%s)", victim_pid)
        finally:
            worker.join(timeout=10)

        # Victim first, so a failure shows the damage, not just the permission.
        assert victim_errors == []  # the victim's query ran to completion
        assert victim.execute("SELECT 1").fetchone() == (1,)
        assert attack_error is not None
        assert "pg_cancel_backend" in str(attack_error)


def test_reader_cannot_terminate_another_reader_session(reader_url: str) -> None:
    with (
        psycopg.connect(reader_url, autocommit=True) as attacker,
        psycopg.connect(reader_url, autocommit=True) as victim,
    ):
        victim_pid = _pid(victim)

        attack_error = _attempt(attacker, "SELECT pg_terminate_backend(%s)", victim_pid)

        assert victim.execute("SELECT 1").fetchone() == (1,)  # the session survived
        assert attack_error is not None
        assert "pg_terminate_backend" in str(attack_error)
