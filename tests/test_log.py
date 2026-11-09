"""stdout is the stdio MCP channel: logging must never write to it."""

from __future__ import annotations

import json
import logging

import pytest

from app.log import configure_logging, get_logger


def test_structlog_writes_json_to_stderr_only(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO")

    get_logger("test").info("hello", tool="run_query")

    captured = capsys.readouterr()
    assert captured.out == ""
    lines = captured.err.strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["event"] == "hello"
    assert record["level"] == "info"
    assert record["tool"] == "run_query"
    assert "timestamp" in record


def test_stdlib_logging_writes_to_stderr_only(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO")

    logging.getLogger("some.library").warning("library message")

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "library message" in captured.err


def test_below_level_is_dropped(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("WARNING")

    get_logger("test").info("too quiet")

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
