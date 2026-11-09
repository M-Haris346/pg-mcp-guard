"""Load the adversarial corpus: tests/validator/corpus/*.toml.

Each [[case]] has:
    id          unique, snake_case
    sql         the query, exactly as the model would send it
    verdict     "allow" or "reject"
    reason      for "reject": the reason code, optionally "code: detail" (detail must match exactly)
    db_test     optional: name of the tests/db test function this entry mirrors
    enforced_by optional: "db" for queries the validator allows but the database must refuse
    note        optional: why the entry exists
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

CORPUS_DIR = Path(__file__).parent / "corpus"


@dataclass(frozen=True)
class Case:
    id: str
    file: str
    sql: str
    verdict: str
    reason: str | None
    db_test: str | None
    enforced_by: str | None
    note: str | None


def load_corpus() -> list[Case]:
    cases: list[Case] = []
    for path in sorted(CORPUS_DIR.glob("*.toml")):
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        for raw in data.get("case", []):
            unknown = set(raw) - {
                "id",
                "sql",
                "verdict",
                "reason",
                "db_test",
                "enforced_by",
                "note",
            }
            if unknown:
                raise ValueError(f"{path.name}: {raw.get('id')}: unknown keys {sorted(unknown)}")
            cases.append(
                Case(
                    id=raw["id"],
                    file=path.name,
                    sql=raw["sql"],
                    verdict=raw["verdict"],
                    reason=raw.get("reason"),
                    db_test=raw.get("db_test"),
                    enforced_by=raw.get("enforced_by"),
                    note=raw.get("note"),
                )
            )
    return cases
