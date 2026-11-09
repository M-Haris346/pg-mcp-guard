from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.config import Settings


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # Isolate from the developer's shell and .env file.
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.delenv("LOG_LEVEL", raising=False)


def test_defaults_to_prod() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.app_env == "prod"
    assert settings.log_level == "INFO"


def test_reads_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.app_env == "dev"
    assert settings.log_level == "DEBUG"


@pytest.mark.parametrize(("var", "value"), [("APP_ENV", "staging"), ("LOG_LEVEL", "LOUD")])
def test_rejects_unknown_values(monkeypatch: pytest.MonkeyPatch, var: str, value: str) -> None:
    monkeypatch.setenv(var, value)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)  # type: ignore[call-arg]
