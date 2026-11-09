"""The real server process: `python -m app.server` over stdio.

These tests start a subprocess, exactly as Claude Desktop / Claude Code / MCP
Inspector would. A stray byte on stdout would corrupt the JSON-RPC stream, so
a working session is itself the proof that logs go to stderr only. On Windows
it also proves the selector event loop: psycopg refuses the default one.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from mcp import Client
from mcp.client.stdio import StdioServerParameters

from app.auth import sign_token
from scripts.seed import ACME, ALICE, MALLORY
from tests.db.helpers import DbTestSettings
from tests.support import UNREACHABLE_URL, last_audit

REPO = Path(__file__).resolve().parents[2]
TEST_JWT_SECRET = b"test-jwt-secret-for-the-stdio-tests-only-0123456789"
ISSUER = AUDIENCE = "pg-mcp-guard"


def _token(
    *,
    user_id: UUID = ALICE,
    tenant_id: UUID = ACME,
    secret: bytes = TEST_JWT_SECRET,
    issued_at: int | None = None,
    ttl_seconds: int = 600,
) -> str:
    return sign_token(
        secret,
        user_id=user_id,
        tenant_id=tenant_id,
        issuer=ISSUER,
        audience=AUDIENCE,
        issued_at=int(time.time()) if issued_at is None else issued_at,
        ttl_seconds=ttl_seconds,
    )


@pytest.fixture
def server_env(db_settings: DbTestSettings, context_key: bytes) -> dict[str, str]:
    """Environment for the server process. Explicit values override .env."""
    env = dict(os.environ)  # PATH, SYSTEMROOT, ... are needed to start Python
    env.update(
        {
            "APP_ENV": "test",
            "LOG_LEVEL": "INFO",
            "READER_DATABASE_URL": db_settings.test_reader_database_url.get_secret_value(),
            "AUDITOR_DATABASE_URL": db_settings.test_auditor_database_url.get_secret_value(),
            "MCP_CONTEXT_KEY": context_key.hex(),
            "JWT_SECRET": TEST_JWT_SECRET.decode(),
            "JWT_ISSUER": ISSUER,
            "JWT_AUDIENCE": AUDIENCE,
            "POOL_OPEN_TIMEOUT_S": "3",
            "MCP_PRINCIPAL_TOKEN": _token(),
            "PYTHONUNBUFFERED": "1",
        }
    )
    return env


async def test_end_to_end_session_over_real_stdio(
    server_env: dict[str, str], migrator: Any
) -> None:
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "app.server"], env=server_env, cwd=REPO
    )
    async with Client(params) as client:
        tools = {t.name for t in (await client.list_tools()).tools}
        result = await client.call_tool(
            "run_query", {"sql": "SELECT DISTINCT tenant_id FROM orders /* t-stdio */"}
        )

    assert tools == {"list_tables", "describe_table", "run_query"}
    assert not result.is_error
    assert result.structured_content is not None
    assert result.structured_content["rows"] == [[str(ACME)]]
    row = last_audit(migrator, "t-stdio")
    assert row is not None and row[:2] == (ALICE, ACME) and row[4] == "allowed"


def _start(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, our own interpreter
        [sys.executable, "-m", "app.server"],
        cwd=REPO,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _startup_failure(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    assert result.returncode == 2
    assert result.stdout == ""  # nothing on the MCP channel, ever
    events = [json.loads(line) for line in result.stderr.splitlines() if line.startswith("{")]
    failures = [e for e in events if e.get("event") == "startup_failed"]
    assert len(failures) == 1, result.stderr
    return failures[0]


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"MCP_PRINCIPAL_TOKEN": ""}, "invalid_principal_token: missing"),
        (
            {"MCP_PRINCIPAL_TOKEN": _token(secret=b"another-secret-of-at-least-32-bytes!!")},
            "invalid_principal_token: bad_signature",
        ),
        (
            {"MCP_PRINCIPAL_TOKEN": _token(issued_at=int(time.time()) - 7200)},
            "invalid_principal_token: expired",
        ),
        (
            {"MCP_PRINCIPAL_TOKEN": _token(ttl_seconds=13 * 3600)},
            "invalid_principal_token: lifetime_too_long",
        ),
        ({"MCP_PRINCIPAL_TOKEN": "not-a-jwt"}, "invalid_principal_token: malformed"),
        ({"MCP_PRINCIPAL_TOKEN": _token(user_id=MALLORY)}, "principal_not_a_member"),
        ({"READER_DATABASE_URL": UNREACHABLE_URL}, "database_unavailable"),
    ],
    ids=[
        "missing_token",
        "bad_signature",
        "expired",
        "lifetime_too_long",
        "malformed",
        "not_a_member",
        "database_unreachable",
    ],
)
def test_server_refuses_to_start(
    server_env: dict[str, str], overrides: dict[str, str], reason: str
) -> None:
    result = _start(server_env | overrides)

    failure = _startup_failure(result)
    assert failure["reason"] == reason
    token = (server_env | overrides)["MCP_PRINCIPAL_TOKEN"]
    if token:
        assert token not in result.stderr  # never logged


def test_invalid_settings_name_the_field_not_the_value(server_env: dict[str, str]) -> None:
    result = _start(server_env | {"JWT_SECRET": "too-short"})

    failure = _startup_failure(result)
    assert failure["reason"] == "invalid_settings"
    assert failure["fields"] == ["jwt_secret"]
    assert "too-short" not in result.stderr
