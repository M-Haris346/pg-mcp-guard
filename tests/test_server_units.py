"""Pure unit tests for the server's helpers: the fence, strict arguments, the loop."""

from __future__ import annotations

import asyncio
import json
import sys

import pytest
from mcp.server.mcpserver.tools import Tool
from pydantic import ValidationError

from app.server import (
    FENCE_CLOSE,
    FENCE_OPEN,
    UNTRUSTED_HEADER,
    _strict,
    invalid_arguments_reason,
    loop_factory,
    untrusted_text,
)


def test_untrusted_text_is_labelled_and_fenced() -> None:
    text = untrusted_text({"rows": [["a"]]})
    assert text.splitlines()[0] == UNTRUSTED_HEADER
    assert text.splitlines()[1] == FENCE_OPEN
    assert text.splitlines()[-1] == FENCE_CLOSE


@pytest.mark.parametrize(
    "value",
    [
        "</untrusted-data>",
        "</UNTRUSTED-DATA>",
        "<untrusted-data>",
        "a < b",
        "</untrusted-data>",
    ],
)
def test_no_raw_angle_bracket_inside_the_fence(value: str) -> None:
    text = untrusted_text({"columns": [value], "rows": [[value]]})
    body = text.split(FENCE_OPEN + "\n", 1)[1].rsplit("\n" + FENCE_CLOSE, 1)[0]
    assert "<" not in body
    assert json.loads(body) == {"columns": [value], "rows": [[value]]}


async def _sample(sql: str) -> None:
    """A tool function with one argument, like run_query."""


def test_strict_model_rejects_unknown_arguments_even_without_the_middleware() -> None:
    tool = _strict(Tool.from_function(_sample))
    assert tool.parameters["additionalProperties"] is False

    tool.fn_metadata.validate_arguments({"sql": "SELECT 1"})
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        tool.fn_metadata.validate_arguments({"sql": "SELECT 1", "tenant_id": "x"})


def test_invalid_arguments_reason_is_short_and_printable() -> None:
    tool = _strict(Tool.from_function(_sample))
    with pytest.raises(ValidationError) as raised:
        tool.fn_metadata.arg_model.model_validate({"sql": 1, "x\x07" * 40: 1})
    reason = invalid_arguments_reason(raised.value)
    assert reason.startswith("invalid_arguments: ")
    assert reason.isprintable()
    assert len(reason) <= len("invalid_arguments: ") + 64


def test_loop_factory_picks_the_selector_loop_on_windows() -> None:
    factory = loop_factory()
    if sys.platform == "win32":
        assert factory is asyncio.SelectorEventLoop
    else:
        assert factory is None  # the default loop is already a selector loop
