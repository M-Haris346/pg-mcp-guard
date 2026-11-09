"""Validator behaviour beyond the corpus: limits, scoping, policy, reasons. Pure."""

from __future__ import annotations

import pytest

from app.validator import DEFAULT_POLICY, REASON_CODES, Policy, Verdict, validate
from tests.validator.corpus import load_corpus

# --- limits -------------------------------------------------------------------


def test_too_long_is_rejected_before_parsing() -> None:
    sql = "SELECT 1" + " " * DEFAULT_POLICY.max_sql_chars
    assert validate(sql) == Verdict(False, "query_too_long")


def test_at_length_limit_is_allowed() -> None:
    sql = "SELECT 1"
    sql += " " * (DEFAULT_POLICY.max_sql_chars - len(sql))
    assert validate(sql).allowed


# Worst-case nesting just under max_sql_chars. Before the validator ran in a
# large-stack thread, these crashed the whole process (native stack overflow
# inside pglast on Windows), which a try/except cannot catch.
DEEP_NESTING = {
    "unary_minus": "SELECT " + "- " * 9990 + "a",
    "not_chain": "SELECT " + "NOT " * 4990 + "true",
    "plus_chain": "SELECT a" + "+a" * 9990,
    "nested_functions": "SELECT " + "lower(" * 2850 + "a" + ")" * 2850,
    "nested_subqueries": "SELECT " + "(SELECT " * 1250 + "1" + ")" * 1250,
    "nested_case": "SELECT " + "CASE WHEN true THEN " * 800 + "1" + " END" * 800,
    "nested_arrays": "SELECT " + "ARRAY[" * 2800 + "1" + "]" * 2800,
}


@pytest.mark.parametrize("sql", DEEP_NESTING.values(), ids=DEEP_NESTING.keys())
def test_deep_nesting_is_rejected_without_crashing(sql: str) -> None:
    assert len(sql) <= DEFAULT_POLICY.max_sql_chars
    assert validate(sql) == Verdict(False, "query_too_complex")


def test_parentheses_alone_do_not_count_as_nesting() -> None:
    # Redundant parentheses produce no tree nodes.
    sql = "SELECT " + "(" * 9990 + "1" + ")" * 9990
    assert validate(sql).allowed


def test_moderate_nesting_is_allowed() -> None:
    sql = "SELECT " + "lower(" * 20 + "name" + ")" * 20 + " FROM customers"
    assert validate(sql).allowed


def test_depth_limit_is_configurable() -> None:
    sql = "SELECT " + "lower(" * 20 + "name" + ")" * 20 + " FROM customers"
    assert validate(sql, Policy(max_depth=10)) == Verdict(False, "query_too_complex")


# --- reasons --------------------------------------------------------------------


def test_reason_strips_control_characters() -> None:
    verdict = validate('SELECT * FROM U&"\\0007\\0008orders\\000A"')
    assert verdict == Verdict(False, "relation_not_allowed: orders")


def test_reason_detail_is_truncated() -> None:
    verdict = validate("SELECT " + "f" * 60 + "_" + "g" * 60 + "(1)")
    assert verdict.reason is not None
    code, detail = verdict.reason.split(": ", 1)
    assert code == "function_not_allowed"
    assert len(detail) <= 64


@pytest.mark.parametrize("secret", ["mcp_", "mcpguard.ctx", "private.", "context_key"])
def test_reasons_never_mention_internals_the_query_did_not(secret: str) -> None:
    for case in load_corpus():
        reason = validate(case.sql).reason or ""
        if secret not in case.sql:
            assert secret not in reason, (case.id, reason)


def test_every_reason_uses_a_documented_code() -> None:
    for case in load_corpus():
        verdict = validate(case.sql)
        if verdict.reason is not None:
            assert verdict.reason.split(":", 1)[0] in REASON_CODES, (case.id, verdict.reason)


def test_syntax_error_reason_is_short_and_printable() -> None:
    verdict = validate("SELECT FROM WHERE \x07 (((")
    assert verdict.reason is not None
    assert verdict.reason.startswith("syntax_error")
    assert verdict.reason.isprintable()


@pytest.mark.parametrize(
    ("sql", "reason"),
    [
        ("INSERT INTO orders DEFAULT VALUES", "statement_not_allowed: INSERT"),
        ("BEGIN", "statement_not_allowed: BEGIN"),
        ("START TRANSACTION", "statement_not_allowed: START"),
        ("SAVEPOINT s", "statement_not_allowed: SAVEPOINT"),
        ("SET x.y = 1", "statement_not_allowed: SET"),
    ],
)
def test_statement_names(sql: str, reason: str) -> None:
    assert validate(sql) == Verdict(False, reason)


# --- validate never raises ---------------------------------------------------------


@pytest.mark.parametrize(
    "sql",
    ["\x00", "﻿SELECT 1", "SELECT '\U0001f600'", "SELECT 1e999999", "(((((", "'", '"', "$$"],
)
def test_odd_input_returns_a_verdict(sql: str) -> None:
    assert isinstance(validate(sql), Verdict)


# --- CTE scoping ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sql", "allowed"),
    [
        ("WITH x AS (SELECT 1) SELECT * FROM x", True),
        ("WITH x AS (SELECT 1) SELECT * FROM (SELECT * FROM x) s", True),  # visible below
        ("WITH x AS (SELECT 1), y AS (SELECT * FROM x) SELECT * FROM y", True),
        ("WITH y AS (SELECT * FROM x), x AS (SELECT 1) SELECT * FROM y", False),
        ("SELECT * FROM (WITH x AS (SELECT 1) SELECT * FROM x) s, x", False),
        ("SELECT (WITH x AS (SELECT 1) SELECT 1), * FROM x", False),
        ("WITH x AS (SELECT 1) SELECT * FROM shop.x", False),
        ("WITH x AS (SELECT * FROM x) SELECT * FROM x", False),  # not recursive: inner x is a table
    ],
)
def test_cte_scope(sql: str, allowed: bool) -> None:
    assert validate(sql).allowed is allowed, validate(sql)


# --- policy ------------------------------------------------------------------------------


def test_custom_policy_allowlists_are_used() -> None:
    policy = Policy(
        schema="s",
        relations=frozenset({"t"}),
        functions=frozenset({"f"}),
        types=frozenset({"int4"}),
        operators=frozenset({"="}),
    )
    assert validate("SELECT f(a)::int FROM s.t WHERE a = 1", policy).allowed
    assert validate("SELECT * FROM shop.orders", policy).reason == (
        "relation_not_allowed: shop.orders"
    )
    assert validate("SELECT lower(a) FROM t", policy).reason == "function_not_allowed: lower"
    assert validate("SELECT a::text FROM t", policy).reason == "type_not_allowed: text"
    assert validate("SELECT a FROM t WHERE a < 1", policy).reason == "operator_not_allowed: <"


def test_default_relations_are_not_catalog_names() -> None:
    # pg_catalog is searched before shop, so a pg_-prefixed allowlisted name
    # could silently resolve to a catalog table. (Checked against the real
    # catalog in tests/db/test_validator_against_db.py.)
    assert not any(name.startswith("pg_") for name in DEFAULT_POLICY.relations)
