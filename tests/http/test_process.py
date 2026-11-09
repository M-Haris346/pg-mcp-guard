"""The real HTTP server process: default bind, remote-bind refusal, and no
token or Authorization header ever reaching the logs (DEBUG level)."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx2
import pytest
from mcp.shared.exceptions import MCPError

from tests.db.helpers import DbTestSettings
from tests.http_support import (
    ACCEPT,
    AUDIENCE,
    ISSUER,
    JWT_SECRET,
    mcp_session,
    mint,
    modern_request,
)
from tests.support import ALICE_AT_ACME, BOB_AT_GLOBEX

REPO = Path(__file__).resolve().parents[2]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


@pytest.fixture
def server_env(db_settings: DbTestSettings, context_key: bytes) -> dict[str, str]:
    env = dict(os.environ)
    for name in list(env):
        if name.startswith("MCP_HTTP_") or name == "MCP_PRINCIPAL_TOKEN":
            del env[name]
    env.update(
        {
            "APP_ENV": "test",
            "LOG_LEVEL": "DEBUG",  # the most verbose the server ever gets
            "READER_DATABASE_URL": db_settings.test_reader_database_url.get_secret_value(),
            "AUDITOR_DATABASE_URL": db_settings.test_auditor_database_url.get_secret_value(),
            "MCP_CONTEXT_KEY": context_key.hex(),
            "JWT_SECRET": JWT_SECRET.decode(),
            "JWT_ISSUER": ISSUER,
            "JWT_AUDIENCE": AUDIENCE,
            "POOL_OPEN_TIMEOUT_S": "5",
            "PYTHONUNBUFFERED": "1",
        }
    )
    return env


def _run_to_exit(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, our own interpreter
        [sys.executable, "-m", "app.server", "--transport", "http"],
        cwd=REPO,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _failure_reason(result: subprocess.CompletedProcess[str]) -> str:
    assert result.returncode == 2
    events = [json.loads(line) for line in result.stderr.splitlines() if line.startswith("{")]
    (failure,) = [e for e in events if e.get("event") == "startup_failed"]
    reason: str = failure["reason"]
    return reason


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"MCP_HTTP_HOST": "0.0.0.0"}, "remote_bind_not_allowed"),  # noqa: S104 - refused
        ({"MCP_HTTP_HOST": "192.0.2.10"}, "remote_bind_not_allowed"),
        (
            {"MCP_HTTP_HOST": "0.0.0.0", "MCP_HTTP_ALLOW_REMOTE": "true"},  # noqa: S104
            "remote_bind_needs_allowed_hosts_and_origins",
        ),
    ],
    ids=["any_address", "public_address", "opt_in_without_allowlists"],
)
def test_non_loopback_bind_needs_explicit_config(
    server_env: dict[str, str], overrides: dict[str, str], reason: str
) -> None:
    assert _failure_reason(_run_to_exit(server_env | overrides)).startswith(reason)


async def _wait_for_port(port: int, process: subprocess.Popen[bytes], wait_s: float = 30.0) -> None:
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"server exited early with {process.returncode}")
        try:
            _, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            await writer.wait_closed()
            return
        except OSError:
            await asyncio.sleep(0.1)
    raise AssertionError("server did not start listening")


async def test_default_bind_and_no_secrets_in_the_logs(
    server_env: dict[str, str], tmp_path: Path
) -> None:
    port = _free_port()
    alice = mint(ALICE_AT_ACME)
    bob = mint(BOB_AT_GLOBEX)
    expired = mint(ALICE_AT_ACME, issued_at=int(time.time()) - 7200)
    forged = mint(ALICE_AT_ACME, secret=b"another-secret-of-at-least-32-bytes!!")
    out, err = tmp_path / "stdout.log", tmp_path / "stderr.log"

    with out.open("wb") as stdout, err.open("wb") as stderr:
        # Popen only starts the process (no blocking wait); asyncio subprocesses
        # are unavailable on Windows' selector loop.
        process = subprocess.Popen(  # noqa: S603, ASYNC220 - fixed argv, own interpreter
            [sys.executable, "-m", "app.server", "--transport", "http"],
            cwd=REPO,
            env=server_env | {"MCP_HTTP_PORT": str(port)},
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
        )
        try:
            await _wait_for_port(port, process)
            url = f"http://127.0.0.1:{port}/mcp"

            # Authenticated work, modern and legacy.
            async with mcp_session(url, alice) as (client, _):
                result = await client.call_tool("run_query", {"sql": "SELECT 1"})
                assert not result.is_error
            async with mcp_session(url, alice, mode="legacy") as (client, http):
                assert not (await client.call_tool("list_tables", {})).is_error
                http.headers["Authorization"] = f"Bearer {bob}"  # session hijack attempt
                with pytest.raises(MCPError):  # the server answers 404
                    await client.call_tool("list_tables", {})

            # Failed authentication and a foreign Host.
            body, headers = modern_request("tools/list")
            async with httpx2.AsyncClient() as raw:
                for token in (expired, forged, "not-a-jwt"):
                    response = await raw.post(
                        url,
                        json=body,
                        headers=headers | {"Authorization": f"Bearer {token}", "Accept": ACCEPT},
                    )
                    assert response.status_code == 401
                response = await raw.post(
                    url,
                    json=body,
                    headers=headers
                    | {
                        "Authorization": f"Bearer {alice}",
                        "Accept": ACCEPT,
                        "Host": "evil.example",
                    },
                )
                assert response.status_code == 421
            await asyncio.sleep(0.5)  # let the 401 audit writes and their logs finish
        finally:
            process.terminate()
            process.wait(timeout=15)

    stdout_text = out.read_text(encoding="utf-8", errors="replace")
    stderr_text = err.read_text(encoding="utf-8", errors="replace")
    logs = stdout_text + stderr_text
    events: list[dict[str, Any]] = [
        json.loads(line) for line in stderr_text.splitlines() if line.startswith("{")
    ]

    starting = [e for e in events if e.get("event") == "server_starting"]
    assert starting and starting[0]["url"] == f"http://127.0.0.1:{port}/mcp"  # loopback default
    assert "Invalid Host header" in logs  # the run really logged (the SDK's warning)
    for secret in (alice, bob, expired, forged, "not-a-jwt"):
        assert secret not in logs
        assert secret.split(".")[-1] not in logs  # not even the signature part
    lowered = logs.lower()
    assert "bearer " not in lowered
    assert "authorization:" not in lowered and '"authorization"' not in lowered
    assert stdout_text == ""  # HTTP mode logs to stderr too
