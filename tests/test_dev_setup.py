"""scripts/dev_setup.py: the .env generation (no Docker needed)."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.config import Settings
from scripts.dev_setup import (
    PLACEHOLDER,
    generate_secrets,
    read_env,
    render_env,
    write_env_if_missing,
)

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / ".env.example"


def _render(port: int = 5432) -> tuple[str, dict[str, str]]:
    values = generate_secrets()
    return render_env(EXAMPLE.read_text(encoding="utf-8"), values, port=port), values


def test_every_change_me_is_replaced() -> None:
    rendered, _ = _render()
    active = [line for line in rendered.splitlines() if line and not line.startswith("#")]
    assert all(PLACEHOLDER not in line for line in active)


def test_secrets_have_valid_lengths_and_formats() -> None:
    _, values = _render()
    assert len(bytes.fromhex(values["MCP_CONTEXT_KEY"])) == 32
    assert len(values["JWT_SECRET"].encode()) >= 32
    for name in ("POSTGRES_PASSWORD", "MCP_MIGRATOR_PASSWORD", "MCP_READER_PASSWORD"):
        assert len(values[name]) >= 24
    assert len(set(values.values())) == len(values)  # all different


def test_urls_carry_the_same_passwords_and_port(tmp_path: Path) -> None:
    rendered, values = _render(port=5433)
    env = tmp_path / ".env"
    env.write_text(rendered, encoding="utf-8")
    parsed = read_env(env)
    assert parsed["POSTGRES_PORT"] == "5433"
    assert parsed["APP_ENV"] == "dev"
    for prefix in ("", "TEST_"):
        assert (
            f"mcp_reader:{values['MCP_READER_PASSWORD']}@127.0.0.1:5433/"
            in parsed[f"{prefix}READER_DATABASE_URL"]
        )
        assert (
            f"mcp_migrator:{values['MCP_MIGRATOR_PASSWORD']}@"
            in parsed[f"{prefix}MIGRATOR_DATABASE_URL"]
        )
        assert (
            f"mcp_auditor:{values['MCP_AUDITOR_PASSWORD']}@"
            in parsed[f"{prefix}AUDITOR_DATABASE_URL"]
        )


def test_generated_env_satisfies_the_server_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = tmp_path / ".env"
    assert write_env_if_missing(env, EXAMPLE) is True
    for name in list(read_env(env)):
        monkeypatch.delenv(name, raising=False)
    settings = Settings(_env_file=env)  # type: ignore[call-arg]
    assert len(settings.context_key_bytes()) == 32
    assert settings.app_env == "dev"


def test_never_overwrites_an_existing_env(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("KEEP=me\n", encoding="utf-8")
    assert write_env_if_missing(env, EXAMPLE) is False
    assert env.read_text(encoding="utf-8") == "KEEP=me\n"


def test_two_runs_produce_different_secrets(tmp_path: Path) -> None:
    first, second = tmp_path / "a.env", tmp_path / "b.env"
    write_env_if_missing(first, EXAMPLE)
    write_env_if_missing(second, EXAMPLE)
    assert read_env(first)["JWT_SECRET"] != read_env(second)["JWT_SECRET"]


def test_unreplaced_placeholder_is_an_error() -> None:
    with pytest.raises(ValueError, match="change-me"):
        render_env("NEW_SECRET=change-me\n", generate_secrets())
