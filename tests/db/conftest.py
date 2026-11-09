"""Database-layer tests.

Every test here talks to Postgres with raw psycopg as the real runtime roles.
No app code and no SQL validator sit in between: these properties must hold
even if the validator has a bug.

The shared fixtures (tests/conftest.py) migrate and seed mcpguard_test once per
session, with a fresh random context key, so tests never depend on the key in
.env.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _database(prepared_database: None) -> None:
    """Every test in tests/db needs the prepared test database."""
