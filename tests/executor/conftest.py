"""Executor integration tests: real pools, real roles, the shared test database.

Fixtures (make_executor, migrator, ...) are in tests/conftest.py; constants and
helpers in tests/support.py.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _database(prepared_database: None) -> None:
    """Every executor test needs the prepared test database."""
