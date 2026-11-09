"""scripts/demo.py stays honest: run it end to end against the test database."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.db.helpers import DbTestSettings

REPO = Path(__file__).resolve().parents[1]
JWT_SECRET = "demo-test-jwt-secret-0123456789abcdef0123456789"


@pytest.fixture
def demo_env(
    prepared_database: None, db_settings: DbTestSettings, context_key: bytes
) -> dict[str, str]:
    env = dict(os.environ)
    env.pop("MCP_PRINCIPAL_TOKEN", None)
    env.update(
        {
            "APP_ENV": "dev",
            "READER_DATABASE_URL": db_settings.test_reader_database_url.get_secret_value(),
            "AUDITOR_DATABASE_URL": db_settings.test_auditor_database_url.get_secret_value(),
            "MIGRATOR_DATABASE_URL": db_settings.test_migrator_database_url.get_secret_value(),
            "MCP_CONTEXT_KEY": context_key.hex(),
            "JWT_SECRET": JWT_SECRET,
            "JWT_ISSUER": "pg-mcp-guard",
            "JWT_AUDIENCE": "pg-mcp-guard",
            "PYTHONUNBUFFERED": "1",
        }
    )
    return env


def _demo(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, our own interpreter
        [sys.executable, "scripts/demo.py", "--no-color"],
        cwd=REPO,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_every_scene_behaves_as_expected(demo_env: dict[str, str]) -> None:
    result = _demo(demo_env)

    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-2000:]
    out = result.stdout
    for key in "abcdefghij":
        assert f"[{key}] " in out
    assert "UNEXPECTED" not in out
    assert [line.strip() for line in out.splitlines()].count("as expected") == 10
    assert "All 10 scenes behaved as expected." in out
    assert "\033[" not in out  # --no-color


def test_refuses_outside_dev(demo_env: dict[str, str]) -> None:
    result = _demo(demo_env | {"APP_ENV": "test"})
    assert result.returncode == 2
    assert "APP_ENV must be 'dev'" in result.stderr
