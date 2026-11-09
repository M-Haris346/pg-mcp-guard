"""scripts/mint_token.py: dev only, prints only the token (subprocess, no database)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from app.auth import HS256Verifier
from scripts.seed import ACME, ALICE

REPO = Path(__file__).resolve().parents[1]
SECRET = "mint-token-test-secret-0123456789abcdef"


def _mint(*args: str, app_env: str = "dev") -> subprocess.CompletedProcess[str]:
    env = dict(os.environ) | {
        "APP_ENV": app_env,
        "JWT_SECRET": SECRET,
        "JWT_ISSUER": "pg-mcp-guard",
        "JWT_AUDIENCE": "pg-mcp-guard",
        "JWT_MAX_LIFETIME_SECONDS": str(12 * 3600),
    }
    return subprocess.run(  # noqa: S603 - fixed argv, our own interpreter
        [sys.executable, "-m", "scripts.mint_token", *args],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_prints_only_a_valid_token_in_dev() -> None:
    result = _mint("--user", "alice", "--tenant", "acme", "--ttl", "15m")

    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert len(lines) == 1  # nothing but the token on stdout
    verifier = HS256Verifier(SECRET.encode(), issuer="pg-mcp-guard", audience="pg-mcp-guard")
    verified = verifier.verify(lines[0])
    assert (verified.principal.user_id, verified.principal.tenant_id) == (ALICE, ACME)


@pytest.mark.parametrize("app_env", ["prod", "test"])
def test_refuses_outside_dev(app_env: str) -> None:
    result = _mint("--user", "alice", "--tenant", "acme", app_env=app_env)
    assert result.returncode == 2
    assert result.stdout == ""
    assert "APP_ENV must be 'dev'" in result.stderr


@pytest.mark.parametrize(
    "args",
    [
        ("--user", "alice", "--tenant", "acme", "--ttl", "13h"),  # over the 12 h maximum
        ("--user", "alice", "--tenant", "acme", "--ttl", "forever"),
        ("--user", "eve", "--tenant", "acme"),
    ],
    ids=["ttl_over_max", "ttl_garbage", "unknown_user"],
)
def test_refuses_bad_arguments(args: tuple[str, ...]) -> None:
    result = _mint(*args)
    assert result.returncode == 2
    assert result.stdout == ""
