from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.config import Settings

VALID_KEY = "ab" * 32  # 32 bytes, hex


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # Isolate from the developer's shell; _env_file=None below ignores .env.
    for var in ("APP_ENV", "LOG_LEVEL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("READER_DATABASE_URL", "postgresql://r:p@localhost/db")
    monkeypatch.setenv("AUDITOR_DATABASE_URL", "postgresql://a:p@localhost/db")
    monkeypatch.setenv("MCP_CONTEXT_KEY", VALID_KEY)


def _settings() -> Settings:
    return Settings(_env_file=None)  # type: ignore[call-arg]


def test_defaults_to_prod() -> None:
    settings = _settings()
    assert settings.app_env == "prod"
    assert settings.log_level == "INFO"


def test_reads_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    settings = _settings()
    assert settings.app_env == "dev"
    assert settings.log_level == "DEBUG"
    assert settings.context_key_bytes() == bytes.fromhex(VALID_KEY)


@pytest.mark.parametrize(("var", "value"), [("APP_ENV", "staging"), ("LOG_LEVEL", "LOUD")])
def test_rejects_unknown_values(monkeypatch: pytest.MonkeyPatch, var: str, value: str) -> None:
    monkeypatch.setenv(var, value)
    with pytest.raises(ValidationError):
        _settings()


@pytest.mark.parametrize(
    ("value", "message"),
    [("ab" * 31, "at least 32 bytes"), ("zz" * 32, "must be hex"), ("change-me", "must be hex")],
)
def test_rejects_weak_context_key(
    monkeypatch: pytest.MonkeyPatch, value: str, message: str
) -> None:
    monkeypatch.setenv("MCP_CONTEXT_KEY", value)
    with pytest.raises(ValidationError, match=message):
        _settings()


@pytest.mark.parametrize("var", ["READER_DATABASE_URL", "AUDITOR_DATABASE_URL", "MCP_CONTEXT_KEY"])
def test_required_values_have_no_default(monkeypatch: pytest.MonkeyPatch, var: str) -> None:
    monkeypatch.delenv(var)
    with pytest.raises(ValidationError):
        _settings()


def test_secrets_are_not_in_repr() -> None:
    assert VALID_KEY not in repr(_settings())
