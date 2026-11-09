"""The corpus must cover every attack the database-layer tests use.

Every test in tests/db marked `attack` or `known_gap` must be named by at least
one corpus entry's db_test, and every db_test must name a real test. A new DB
attack test without a matching corpus entry fails here.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from collections.abc import Callable
from typing import Any

import tests.db
from tests.validator.corpus import load_corpus

MARKERS = {"attack", "known_gap"}


def _db_test_functions() -> dict[str, Callable[..., Any]]:
    functions: dict[str, Callable[..., Any]] = {}
    for module_info in pkgutil.iter_modules(tests.db.__path__):
        if not module_info.name.startswith("test_"):
            continue
        module = importlib.import_module(f"tests.db.{module_info.name}")
        for name, obj in inspect.getmembers(module, inspect.isfunction):
            if name.startswith("test_") and obj.__module__ == module.__name__:
                functions[name] = obj
    return functions


def _marker_names(func: Callable[..., Any]) -> set[str]:
    return {mark.name for mark in getattr(func, "pytestmark", [])}


def test_every_db_attack_test_has_a_corpus_entry() -> None:
    functions = _db_test_functions()
    marked = {name for name, f in functions.items() if _marker_names(f) & MARKERS}
    assert len(marked) >= 15  # sanity: the markers are actually there

    referenced = {c.db_test for c in load_corpus() if c.db_test}
    missing = sorted(marked - referenced)
    assert missing == [], f"DB attack tests with no corpus entry: {missing}"


def test_every_db_test_reference_exists() -> None:
    functions = _db_test_functions()
    dangling = sorted({c.db_test for c in load_corpus() if c.db_test} - set(functions))
    assert dangling == [], f"corpus db_test names that match no test: {dangling}"
