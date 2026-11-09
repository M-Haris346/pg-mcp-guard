# ADR 0003: SQL validator built on pglast, deny by default

Status: accepted (Phase 2)

## Context

The validator is the second layer. The database (role, grants, RLS, role limits) is the first,
and `tests/db` proves it holds with the validator switched off. The validator exists to:

- give the model a clear, early reason (`function_not_allowed: pg_sleep`) instead of a raw
  database error;
- close what the database layer cannot: a model with a plain connection could
  `SET statement_timeout = 0` (ADR 0002, residual risk 3) or take session advisory locks;
- shrink what reaches the database: no catalog reads, no exotic syntax.

## Decision

**Parser: pglast 8.7** (libpg_query, PostgreSQL's own grammar, bundled version 18.6). The database
runs PostgreSQL 18.6 (ADR 0001).

- Rejected **sqlglot**: it is a separate, multi-dialect grammar. Any place where it parses a
  string differently from Postgres (nested comments, dollar quoting, `U&""` identifiers,
  `standard_conforming_strings`, operator lexing) is a bypass. With libpg_query the validator
  sees the same tree the server will build.
- Rejected **regexes / token scanning**: they cannot tell a function name from the same text
  inside a string or a comment. The corpus includes such cases.

**Policy: exactly one statement, a `SelectStmt`, and deny by default at every level** of the tree,
including ORDER BY, LATERAL, VALUES, subqueries, CASE, FILTER, windows, LIMIT, set operations and
CTEs:

| Allowlist | Notes |
|---|---|
| Node types | ~35 classes. Anything else, including syntax added in a future Postgres, is `syntax_not_allowed`: functions in FROM, TABLESAMPLE, `$1`, COLLATE, `(x).field`, XML/JSON constructs, GROUPING() |
| Relations | Allowlisted names in `shop`, unqualified or `shop.`-qualified. A test asserts the list equals the reader's actual grants |
| Functions | Unqualified or `pg_catalog.`-qualified names, matched by name. A DB test asserts every reachable overload is in pg_catalog, not VOLATILE and not SECURITY DEFINER |
| Types (casts) | 16 scalar types plus arrays of them. Every `reg*` type, `oid`, `json`, `bytea`, composite types etc. are rejected |
| Operators | Comparison, arithmetic, `\|\|`, the LIKE family. Regex operators and `SIMILAR TO` are rejected (ReDoS) |
| SQL value functions | Date/time only. `CURRENT_USER`, `USER`, `SESSION_USER`, `CURRENT_ROLE`, `CURRENT_SCHEMA` and `CURRENT_CATALOG` would reveal internal names |

**System columns** (`ctid`, `xmin`, `xmax`, `cmin`, `cmax`, `tableoid`) are rejected as
`column_not_allowed: <name>`. The check applies to any column reference whose last part is one
of these, bare or qualified (`o.xmin`, `shop.orders.ctid`). Quoted and `U&""` forms are covered,
because the parser has already decoded them. Why:
- `xmin` and `xmax` expose transaction ids, a weak side channel on other tenants' write activity
  (the ids are global across tenants);
- `cmin` and `cmax` expose command ids;
- `ctid` exposes physical row positions;
- `tableoid` exposes internal oids.

Output aliases (`AS xmin`, `xmin_count`) are not column references, so they stay allowed. Known
over-block, accepted: a derived column the query itself names `xmin` cannot be read back by name
in an outer query.

**Rejected outright, each with a clear reason:**
- `SELECT INTO`;
- locking clauses, anywhere in the tree;
- data-modifying CTEs, including unreferenced or nested ones;
- **all** recursive CTEs, because an unbounded `UNION ALL` loop is CPU-only;
- NUL characters, because C-string parsers would not see past one.

**CTE scoping follows Postgres exactly**, because a CTE name hides a table name:
- in a non-recursive WITH, a CTE sees only the CTEs before it, and the main query sees all of them;
- a CTE defined inside a subquery is invisible outside it;
- a schema-qualified name never refers to a CTE.

So `WITH users AS (...)` inside a subquery cannot unlock an outer `FROM users`.

**Removed from the agreed allowlist:** `substring`. Its `substring(text, text)` overload is a
regex, and a validator that matches by name cannot tell the overloads apart. `substr`, `left` and
`right` cover substring extraction.

**Memory-heavy allowed functions:** `array_agg` and `string_agg` build one value from many rows.
They are bounded by the role `statement_timeout` and, in Phase 3, by the executor's response-size
cap. A large cross join (`orders a, orders b, orders c, orders d`) is allowed, and the role
`statement_timeout` bounds it.

**Process safety:** pglast builds its Python tree recursively through C frames. On Windows' 1 MB
main-thread stack, deeply nested input (`SELECT - - - … a`) overflowed the native stack and killed
the process. No `try/except` can catch that, so it was a one-query denial of service against the
server. `validate()` therefore parses and walks in a dedicated thread with a 64 MB stack, plus a
200-level walk depth limit and a 20 000-character length limit. Tests feed worst-case nesting at
the length limit.

## What the validator does not check, and why

- **Column privileges.** Resolving columns through aliases, subqueries, `USING` joins, whole-row
  references (`SELECT c::text FROM customers c`) and `*` would re-implement the planner, and any
  mismatch would be a false sense of safety. The column grants enforce this; the corpus marks such
  queries `enforced_by = "db"`, and a DB test runs them and asserts the refusal.
- **Row-level security.** Identity is never in the SQL (rule 1). RLS uses the signed context
  (ADR 0002).

## Consequences

- Allowed queries are a deliberately small dialect. Every allowed corpus entry is run against the
  real database as `mcp_reader`, which proves the allowed queries really run and that the
  validator's view agrees with Postgres's.
- Adding a function, type or operator means editing `app/validator.py`; the DB consistency tests
  then check it.
- Name-based matching relies on nothing in `shop` shadowing a built-in. A DB test asserts `shop`
  holds no functions, operators or non-relation types, and that no allowlisted relation name exists
  in `pg_catalog`.
- Corpus coverage: every `tests/db` test marked `attack` or `known_gap` must be referenced by a
  corpus entry. A meta-test enforces it.
