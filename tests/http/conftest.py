"""HTTP transport tests: a real uvicorn server in this process, real database.

Each test gets a fresh app (the SDK's session manager runs once per app) on a
pre-bound 127.0.0.1:0 socket. The http_server fixture is in tests/conftest.py,
helpers in tests/http_support.py.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _database(prepared_database: None) -> None:
    """Every HTTP test needs the prepared test database."""
