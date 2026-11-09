"""What the model may see of the schema: allowlisted relations, granted columns.

Used by the list_tables and describe_table tools. The SQL here is trusted (it is
part of this repo, not written by the model) and runs as mcp_reader, so
has_column_privilege reports exactly what the reader role may SELECT: columns
the role cannot read (customers.email, customers.phone) are never listed.
A relation is listed only if it is in the validator's allowlist *and* granted.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

CATALOG_SQL = """
SELECT c.relname, c.relkind, a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod)
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
 WHERE n.nspname = %s
   AND c.relname = ANY(%s)
   AND a.attnum > 0
   AND NOT a.attisdropped
   AND pg_catalog.has_column_privilege(c.oid, a.attnum, 'SELECT')
 ORDER BY c.relname, a.attnum
"""

_KINDS = {"r": "table", "p": "table", "v": "view", "m": "view"}


@dataclass(frozen=True)
class Column:
    name: str
    type: str


@dataclass(frozen=True)
class Relation:
    name: str
    kind: str  # "table" | "view"
    columns: tuple[Column, ...]


@dataclass(frozen=True)
class CatalogResult:
    relations: list[Relation]


def relations_from_rows(rows: Iterable[Sequence[Any]]) -> list[Relation]:
    """Group (relname, relkind, column, type) rows, keeping their order."""
    grouped: dict[str, tuple[str, list[Column]]] = {}
    for relname, relkind, column, type_name in rows:
        kind, columns = grouped.setdefault(relname, (_KINDS.get(relkind, "table"), []))
        columns.append(Column(name=column, type=type_name))
    return [
        Relation(name=name, kind=kind, columns=tuple(columns))
        for name, (kind, columns) in grouped.items()
    ]


def allowlisted_name(name: str, schema: str, relations: frozenset[str]) -> str | None:
    """'orders' or 'shop.orders' -> 'orders' if allowlisted, else None.

    Exact match only: no identifier quoting or case folding is interpreted, so
    there is nothing to bypass. list_tables shows the exact names.
    """
    bare = name.removeprefix(f"{schema}.")
    return bare if bare in relations else None
