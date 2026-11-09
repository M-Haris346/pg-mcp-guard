"""The Phase 6 gap-check cases through the real executor, validator OFF.

Before the fix, model SQL could lift its own settings with set_config(..., false).
Evidence from the gap check (ADR 0002): statement_timeout lifted for a later
FETCH and lock_timeout lifted for a runtime lock wait were still stopped by the
executor deadline, but work_mem (memory) and idle_in_transaction_session_timeout
(a stalled server process) were not bounded at the database layer.

Now set_config is revoked from the reader: each attempt is refused at once,
mapped to function_not_allowed and audited, and the connection stays usable.
"""

from __future__ import annotations

import time
from typing import Any

import pytest

from app.executor import Executor, QueryResult, ToolError
from app.server import startup_problem
from tests.support import ALICE_AT_ACME, ExecutorFactory, allow_all, last_audit

CASES = {
    # A: lift statement_timeout, sleep in the same FETCH.
    "A_statement_timeout_same_fetch": (
        "SELECT set_config('statement_timeout','0',false), pg_sleep(10)"
    ),
    # B: lift statement_timeout, the slow work lands in the second FETCH.
    "B_statement_timeout_later_fetch": (
        "SELECT set_config('statement_timeout','0',false),"
        " pg_sleep(CASE WHEN g > 50 THEN 10 ELSE 0 END) FROM generate_series(1, 100) AS g"
    ),
    # C': lift lock_timeout and statement_timeout, wait on a lock at runtime.
    "C_lock_timeout_runtime_wait": (
        "SELECT set_config('statement_timeout','0',false), set_config('lock_timeout','0',false),"
        " CASE WHEN g > 50 THEN pg_advisory_xact_lock(4242)::text END"
        " FROM generate_series(1, 100) AS g"
    ),
    # D: raise work_mem (memory was bounded only by time).
    "D_work_mem": "SELECT set_config('work_mem','2GB',false)",
    # E: lift the idle-in-transaction bound (unbounded if the server stalls).
    "E_idle_in_transaction": "SELECT set_config('idle_in_transaction_session_timeout','0',false)",
}


async def _pid(executor: Executor) -> int:
    result = await executor.run_query(ALICE_AT_ACME, "SELECT pg_backend_pid()")
    assert isinstance(result, QueryResult)
    pid = result.rows[0][0]
    assert isinstance(pid, int)
    return pid


@pytest.mark.parametrize("case", CASES, ids=list(CASES))
async def test_lifting_a_setting_is_refused_audited_and_harmless(
    make_executor: ExecutorFactory, migrator: Any, case: str
) -> None:
    executor = await make_executor(validator=allow_all, reader_max=1)
    before = await _pid(executor)
    marker = f"t-guc-{case}"

    started = time.monotonic()
    result = await executor.run_query(ALICE_AT_ACME, f"{CASES[case]} /* {marker} */")
    elapsed = time.monotonic() - started

    assert result == ToolError("function_not_allowed: set_config")
    assert elapsed < 1.0  # refused before anything ran, not timed out
    row = last_audit(migrator, marker)
    assert row is not None and row[4:6] == ("error", "function_not_allowed: set_config")
    # Nothing was cancelled, so the connection is fine to reuse.
    assert await _pid(executor) == before


async def test_same_later_fetch_load_without_set_config_is_still_bounded(
    make_executor: ExecutorFactory,
) -> None:
    # Control for B: the second FETCH gets a fresh 3 s server timer.
    executor = await make_executor(validator=allow_all)
    started = time.monotonic()
    result = await executor.run_query(
        ALICE_AT_ACME,
        "SELECT pg_sleep(CASE WHEN g > 50 THEN 10 ELSE 0 END) FROM generate_series(1, 100) AS g",
    )
    assert result == ToolError("query_timeout")
    assert time.monotonic() - started < 4.5


async def test_startup_check_passes_on_a_hardened_database(make_executor: ExecutorFactory) -> None:
    executor = await make_executor()
    assert await executor.reader_can_set_config() is False
    assert await startup_problem(executor, ALICE_AT_ACME) is None


async def test_startup_check_refuses_a_reader_that_can_set_config() -> None:
    class Unhardened:
        async def reader_can_set_config(self) -> bool:
            return True

        async def is_member(self, principal: Any) -> bool:
            raise AssertionError("must refuse before the membership check")

    assert await startup_problem(Unhardened(), ALICE_AT_ACME) == "reader_can_set_config"  # type: ignore[arg-type]
    assert await startup_problem(Unhardened(), None) == "reader_can_set_config"  # type: ignore[arg-type]
