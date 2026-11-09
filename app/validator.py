"""SQL policy for model-written queries (CLAUDE.md rule 6, ADR 0003).

The validator is the *second* layer: the database (roles, grants, RLS, limits)
must hold on its own, and tests/db proves it with this module switched off.

Design:
- Parse with pglast (libpg_query, PostgreSQL's own parser, same version as the
  server), so the validator sees exactly the statement the server would run.
- Exactly one statement, and it must be a SELECT.
- Walk the *whole* tree and deny by default, at every level: node types,
  relations, functions, types and operators each have an allowlist.
  Syntax nobody reviewed is rejected, not silently accepted.

Not checked here (enforced by the database, ADR 0003): column privileges and
row-level security.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable
from dataclasses import dataclass, field

import pglast
from pglast import ast, enums

# Every reason code validate() can return. Reasons are "code" or "code: detail".
REASON_CODES = frozenset(
    {
        "empty_query",
        "query_too_long",
        "query_too_complex",
        "syntax_error",
        "multiple_statements",
        "statement_not_allowed",
        "select_into",
        "locking_clause",
        "data_modifying_cte",
        "recursive_cte",
        "relation_not_allowed",
        "function_not_allowed",
        "type_not_allowed",
        "operator_not_allowed",
        "syntax_not_allowed",
        "column_not_allowed",
    }
)

# Node classes that may appear anywhere in an allowed query. Everything else
# (functions in FROM, TABLESAMPLE, $1 params, COLLATE, (x).field, XML/JSON
# constructs, and any syntax added in future Postgres versions) is rejected.
ALLOWED_NODES = frozenset(
    {
        "SelectStmt",
        "ResTarget",
        "ColumnRef",
        "A_Star",
        "A_Const",
        "String",
        "Integer",
        "Float",
        "Boolean",
        "BitString",
        "A_Expr",
        "BoolExpr",
        "NullTest",
        "BooleanTest",
        "FuncCall",
        "TypeCast",
        "TypeName",
        "CaseExpr",
        "CaseWhen",
        "CoalesceExpr",
        "MinMaxExpr",
        "SQLValueFunction",
        "SubLink",
        "RangeVar",
        "RangeSubselect",
        "JoinExpr",
        "Alias",
        "SortBy",
        "WindowDef",
        "WithClause",
        "CommonTableExpr",
        "GroupingSet",
        "A_ArrayExpr",
        "RowExpr",
    }
)

DEFAULT_RELATIONS = frozenset(
    {"tenants", "customers", "products", "orders", "order_items", "order_summary"}
)

# Matched by name, so every pg_catalog overload of a name is allowed.
# tests/db/test_validator_against_db.py checks that no overload of these is
# volatile or SECURITY DEFINER, and that none exists outside pg_catalog.
# Left out on purpose: repeat/lpad/rpad/array_fill/generate_series (memory or
# CPU bombs), regexp_* and substring (substring(text, text) is a regex: ReDoS),
# random (volatile), format, md5, and everything that reads settings, files,
# catalogs or other sessions.
DEFAULT_FUNCTIONS = frozenset(
    {
        # aggregates
        "count", "sum", "avg", "min", "max", "string_agg", "array_agg",
        "bool_and", "bool_or", "every", "stddev", "stddev_pop", "stddev_samp",
        "variance", "var_pop", "var_samp", "percentile_cont", "percentile_disc", "mode",
        # window functions
        "row_number", "rank", "dense_rank", "percent_rank", "cume_dist", "ntile",
        "lag", "lead", "first_value", "last_value", "nth_value",
        # math
        "abs", "round", "ceil", "ceiling", "floor", "trunc", "mod", "sign", "sqrt", "power",
        # strings (trim(...) parses to btrim/ltrim/rtrim)
        "lower", "upper", "initcap", "length", "char_length", "substr", "left", "right",
        "btrim", "ltrim", "rtrim", "concat", "concat_ws", "replace", "split_part",
        "strpos", "position", "starts_with", "reverse",
        # date / time (AT TIME ZONE parses to timezone)
        "now", "date_trunc", "date_part", "extract", "age", "make_date", "to_char", "timezone",
    }
)  # fmt: skip

# Cast target types, as the parser names them (integer -> int4, boolean -> bool,
# timestamp with time zone -> timestamptz, char(n) -> bpchar ...).
DEFAULT_TYPES = frozenset(
    {
        "int2", "int4", "int8", "numeric", "float4", "float8", "text", "varchar",
        "bpchar", "bool", "date", "time", "timestamp", "timestamptz", "interval", "uuid",
    }
)  # fmt: skip

# Comparison, arithmetic, concatenation, and the LIKE family (~~ is LIKE).
# Regex operators (~, ~*, !~ ...) are left out: ReDoS.
DEFAULT_OPERATORS = frozenset(
    {"=", "<>", "<", ">", "<=", ">=", "+", "-", "*", "/", "%", "||", "~~", "!~~", "~~*", "!~~*"}
)

# No-parenthesis keywords like CURRENT_DATE. CURRENT_USER, SESSION_USER, USER,
# CURRENT_ROLE, CURRENT_SCHEMA and CURRENT_CATALOG are left out: they reveal
# internal role and database names.
_SVF = enums.SQLValueFunctionOp
DEFAULT_SQL_VALUE_FUNCTIONS = frozenset(
    {
        _SVF.SVFOP_CURRENT_DATE,
        _SVF.SVFOP_CURRENT_TIME,
        _SVF.SVFOP_CURRENT_TIME_N,
        _SVF.SVFOP_CURRENT_TIMESTAMP,
        _SVF.SVFOP_CURRENT_TIMESTAMP_N,
        _SVF.SVFOP_LOCALTIME,
        _SVF.SVFOP_LOCALTIME_N,
        _SVF.SVFOP_LOCALTIMESTAMP,
        _SVF.SVFOP_LOCALTIMESTAMP_N,
    }
)

_AEK = enums.A_Expr_Kind
# A_Expr kinds whose `name` is a real operator that must be on the allowlist.
_OPERATOR_KINDS = frozenset(
    {
        _AEK.AEXPR_OP,
        _AEK.AEXPR_OP_ANY,
        _AEK.AEXPR_OP_ALL,
        _AEK.AEXPR_DISTINCT,
        _AEK.AEXPR_NOT_DISTINCT,
        _AEK.AEXPR_NULLIF,
        _AEK.AEXPR_IN,
        _AEK.AEXPR_LIKE,
        _AEK.AEXPR_ILIKE,
    }
)

_STATEMENT_NAMES = {
    "InsertStmt": "INSERT",
    "UpdateStmt": "UPDATE",
    "DeleteStmt": "DELETE",
    "MergeStmt": "MERGE",
    "TruncateStmt": "TRUNCATE",
    "VariableSetStmt": "SET",
    "VariableShowStmt": "SHOW",
    "CreateStmt": "CREATE TABLE",
    "CreateTableAsStmt": "CREATE TABLE AS",
    "CreateFunctionStmt": "CREATE FUNCTION",
    "DropStmt": "DROP",
    "AlterTableStmt": "ALTER TABLE",
    "ExplainStmt": "EXPLAIN",
    "CopyStmt": "COPY",
    "DoStmt": "DO",
    "CallStmt": "CALL",
    "LockStmt": "LOCK",
    "PrepareStmt": "PREPARE",
    "ExecuteStmt": "EXECUTE",
    "DiscardStmt": "DISCARD",
    "ListenStmt": "LISTEN",
    "NotifyStmt": "NOTIFY",
    "VacuumStmt": "VACUUM",
    "GrantStmt": "GRANT",
}

_MAX_DETAIL = 64

# System columns every table has. xmin/xmax/cmin/cmax expose transaction and
# command ids (a weak side channel on other tenants' write activity); ctid
# exposes physical row positions; tableoid exposes internal oids. Rejected
# wherever a column reference ends in one, bare (xmin) or qualified (o.xmin).
SYSTEM_COLUMNS = frozenset({"ctid", "xmin", "xmax", "cmin", "cmax", "tableoid"})

# pglast builds its Python tree recursively through C frames. On a 1 MB thread
# stack (the Windows main thread) deeply nested input such as "- - - ... x"
# overflows the *native* stack and kills the process before Python's
# RecursionError can fire. Parsing and walking therefore run in a dedicated
# thread with a large stack. Tested with worst-case nesting at max_sql_chars
# (tests/validator/test_validator.py); raise this with max_sql_chars.
_PARSE_STACK_BYTES = 64 * 1024 * 1024
# threading.stack_size() is process-global: serialise the set/start/restore.
_stack_size_lock = threading.Lock()


@dataclass(frozen=True)
class Policy:
    schema: str = "shop"
    relations: frozenset[str] = DEFAULT_RELATIONS
    functions: frozenset[str] = DEFAULT_FUNCTIONS
    types: frozenset[str] = DEFAULT_TYPES
    operators: frozenset[str] = DEFAULT_OPERATORS
    sql_value_functions: frozenset[enums.SQLValueFunctionOp] = field(
        default=DEFAULT_SQL_VALUE_FUNCTIONS
    )
    max_sql_chars: int = 20_000
    max_depth: int = 200


DEFAULT_POLICY = Policy()


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reason: str | None = None  # None when allowed


class _Rejected(Exception):
    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.reason = code if detail is None else f"{code}: {_clean(detail)}"


def _clean(detail: str) -> str:
    """Make a detail safe to show the model: printable, short."""
    printable = "".join(ch for ch in detail if ch.isprintable())
    return printable[:_MAX_DETAIL]


def _names(nodes: Iterable[ast.Node] | None) -> tuple[str, ...]:
    """('pg_catalog', 'lower') from a tuple of String nodes."""
    return tuple(n.sval or "" for n in nodes or () if isinstance(n, ast.String))


def validate(sql: str, policy: Policy = DEFAULT_POLICY) -> Verdict:
    """Return whether sql may run. Never raises for any input string."""
    result: list[Verdict] = []
    failure: list[BaseException] = []

    def run() -> None:
        try:
            _check(sql, policy)
            result.append(Verdict(allowed=True))
        except _Rejected as rejected:
            result.append(Verdict(allowed=False, reason=rejected.reason))
        except BaseException as exc:  # re-raised in the caller's thread below
            failure.append(exc)

    with _stack_size_lock:
        previous = threading.stack_size(_PARSE_STACK_BYTES)
        try:
            worker = threading.Thread(target=run, name="sql-validator")
            worker.start()
        finally:
            threading.stack_size(previous)
    worker.join()

    if failure:
        raise failure[0]  # a bug in the validator itself, not a verdict
    return result[0]


def _check(sql: str, policy: Policy) -> None:
    if not sql.strip():
        raise _Rejected("empty_query")
    if len(sql) > policy.max_sql_chars:
        raise _Rejected("query_too_long")
    # libpg_query and libpq both treat the text as a C string: anything after a
    # NUL would be invisible to the parser. Refuse rather than guess.
    if "\x00" in sql:
        raise _Rejected("syntax_error", "NUL character")

    try:
        statements = pglast.parse_sql(sql)
    except pglast.parser.ParseError as exc:
        raise _Rejected("syntax_error", str(exc)) from None
    except RecursionError:
        # Deeply nested input can exhaust Python's stack while pglast builds
        # the tree.
        raise _Rejected("query_too_complex") from None

    if len(statements) == 0:
        raise _Rejected("empty_query")
    if len(statements) > 1:
        raise _Rejected("multiple_statements")

    stmt = statements[0].stmt
    if not isinstance(stmt, ast.SelectStmt):
        raise _Rejected("statement_not_allowed", _statement_name(stmt))

    try:
        _Walker(policy).select(stmt, frozenset(), 0)
    except RecursionError:
        raise _Rejected("query_too_complex") from None


def _statement_name(stmt: ast.Node | None) -> str:
    if isinstance(stmt, ast.TransactionStmt) and stmt.kind is not None:
        return str(stmt.kind.name).removeprefix("TRANS_STMT_")
    name = type(stmt).__name__
    return _STATEMENT_NAMES.get(name, name)


class _Walker:
    """Recursive walk with CTE scope tracking. Raises _Rejected on the first problem."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    # --- statements ---------------------------------------------------------

    def select(self, stmt: ast.SelectStmt, ctes: frozenset[str], depth: int) -> None:
        self._depth(depth)
        if stmt.intoClause is not None:
            raise _Rejected("select_into")
        if stmt.lockingClause:
            raise _Rejected("locking_clause")

        scope = ctes
        if stmt.withClause is not None:
            scope = self._with(stmt.withClause, ctes, depth + 1)

        for name in stmt:
            if name == "withClause":
                continue
            self._value(getattr(stmt, name), scope, depth + 1)

    def _with(self, clause: ast.WithClause, ctes: frozenset[str], depth: int) -> frozenset[str]:
        """Validate each CTE and return the scope the main query sees.

        Non-recursive WITH: a CTE sees the outer scope plus the CTEs defined
        *before* it; the main query sees all of them. (Recursive WITH is
        rejected, so the "sees itself and later siblings" case never arises.)
        """
        if clause.recursive:
            raise _Rejected("recursive_cte")
        scope = ctes
        for cte in clause.ctes or ():
            if not isinstance(cte, ast.CommonTableExpr):
                raise _Rejected("syntax_not_allowed", type(cte).__name__)
            for name in cte:
                if name == "ctequery":
                    continue
                self._value(getattr(cte, name), scope, depth + 1)
            if not isinstance(cte.ctequery, ast.SelectStmt):
                raise _Rejected("data_modifying_cte", _statement_name(cte.ctequery))
            self.select(cte.ctequery, scope, depth + 1)
            scope = scope | {cte.ctename or ""}
        return scope

    # --- generic walk -------------------------------------------------------

    def _value(self, value: object, ctes: frozenset[str], depth: int) -> None:
        if isinstance(value, tuple):
            for item in value:
                self._value(item, ctes, depth)
        elif isinstance(value, ast.Node):
            self._node(value, ctes, depth)
        # str / int / bool / enum / None: leaf values, nothing to check

    def _node(self, node: ast.Node, ctes: frozenset[str], depth: int) -> None:
        self._depth(depth)
        kind = type(node).__name__

        # Clear reasons for things the generic allowlist would also reject.
        if isinstance(node, ast.IntoClause):
            raise _Rejected("select_into")
        if isinstance(node, ast.LockingClause):
            raise _Rejected("locking_clause")
        if kind not in ALLOWED_NODES:
            raise _Rejected("syntax_not_allowed", kind)

        if isinstance(node, ast.SelectStmt):
            self.select(node, ctes, depth)
            return
        if isinstance(node, ast.WithClause | ast.CommonTableExpr):
            # Only valid directly under a SelectStmt, which handles them.
            raise _Rejected("syntax_not_allowed", kind)

        if isinstance(node, ast.RangeVar):
            self._relation(node, ctes)
        elif isinstance(node, ast.ColumnRef):
            # The parser has already folded case and decoded quotes / U&"",
            # so "xmin" and U&"\0078min" arrive as plain xmin.
            fields = _names(node.fields)
            if fields and fields[-1] in SYSTEM_COLUMNS:
                raise _Rejected("column_not_allowed", fields[-1])
        elif isinstance(node, ast.FuncCall):
            self._function(_names(node.funcname))
        elif isinstance(node, ast.SQLValueFunction):
            if node.op not in self.policy.sql_value_functions:
                op = node.op.name if node.op is not None else "unknown"
                raise _Rejected("function_not_allowed", op.removeprefix("SVFOP_").lower())
        elif isinstance(node, ast.TypeName):
            self._type(node)
        elif isinstance(node, ast.A_Expr):
            self._a_expr(node)
        elif isinstance(node, ast.SubLink):
            if node.operName:
                self._operator(_names(node.operName))
        elif isinstance(node, ast.SortBy):
            if node.useOp:  # ORDER BY x USING <op>
                self._operator(_names(node.useOp))

        for name in node:
            self._value(getattr(node, name), ctes, depth + 1)

    def _depth(self, depth: int) -> None:
        if depth > self.policy.max_depth:
            raise _Rejected("query_too_complex")

    # --- individual checks --------------------------------------------------

    def _relation(self, rv: ast.RangeVar, ctes: frozenset[str]) -> None:
        relname = rv.relname or ""
        if rv.catalogname:
            raise _Rejected("relation_not_allowed", f"{rv.catalogname}.{rv.schemaname}.{relname}")
        if rv.schemaname is None:
            # An unqualified name that matches a CTE in scope is that CTE.
            if relname in ctes:
                return
            if relname in self.policy.relations:
                return
            raise _Rejected("relation_not_allowed", relname)
        # Qualified names never refer to a CTE.
        if rv.schemaname == self.policy.schema and relname in self.policy.relations:
            return
        raise _Rejected("relation_not_allowed", f"{rv.schemaname}.{relname}")

    def _function(self, names: tuple[str, ...]) -> None:
        if (len(names) == 1 or (len(names) == 2 and names[0] == "pg_catalog")) and names[
            -1
        ] in self.policy.functions:
            return
        raise _Rejected("function_not_allowed", ".".join(names))

    def _type(self, tn: ast.TypeName) -> None:
        names = _names(tn.names)
        if tn.pct_type:
            raise _Rejected("type_not_allowed", "%TYPE")
        if tn.setof:
            raise _Rejected("type_not_allowed", "SETOF")
        if (
            names
            and (len(names) == 1 or (len(names) == 2 and names[0] == "pg_catalog"))
            and names[-1] in self.policy.types
        ):
            return
        raise _Rejected("type_not_allowed", ".".join(names))

    def _a_expr(self, expr: ast.A_Expr) -> None:
        if expr.kind == _AEK.AEXPR_SIMILAR:
            raise _Rejected("operator_not_allowed", "SIMILAR TO")
        if expr.kind in _OPERATOR_KINDS:
            self._operator(_names(expr.name))
        # BETWEEN variants carry a keyword, not an operator, in `name`.

    def _operator(self, names: tuple[str, ...]) -> None:
        if (len(names) == 1 or (len(names) == 2 and names[0] == "pg_catalog")) and names[
            -1
        ] in self.policy.operators:
            return
        raise _Rejected("operator_not_allowed", ".".join(names))
