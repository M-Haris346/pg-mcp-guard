"""Structured JSON logging to stderr.

stdout is the stdio MCP transport: any stray byte written there corrupts the
JSON-RPC stream. So every log line, ours and the stdlib's, goes to stderr.
"""

from __future__ import annotations

import logging
import sys

import structlog


class _StderrLoggerFactory:
    """Creates a PrintLogger bound to the *current* sys.stderr.

    Looked up per logger rather than once at import, so a redirected stderr
    (e.g. pytest capture) is respected.
    """

    def __call__(self, *args: object) -> structlog.PrintLogger:
        return structlog.PrintLogger(file=sys.stderr)


def configure_logging(level: str = "INFO") -> None:
    numeric_level = logging.getLevelNamesMapping()[level]

    # Libraries that use the stdlib logger (psycopg, mcp) also go to stderr.
    # force=True replaces handlers that an earlier import may have installed.
    logging.basicConfig(stream=sys.stderr, level=numeric_level, format="%(message)s", force=True)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        logger_factory=_StderrLoggerFactory(),
        cache_logger_on_first_use=False,
    )


def get_logger(name: str | None = None) -> structlog.typing.FilteringBoundLogger:
    logger: structlog.typing.FilteringBoundLogger = structlog.get_logger(name)
    return logger
