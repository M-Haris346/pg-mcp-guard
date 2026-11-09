"""Run every adversarial-corpus entry through the validator. Pure: no database."""

from __future__ import annotations

import pytest

from app.validator import REASON_CODES, validate
from tests.validator.corpus import Case, load_corpus

CASES = load_corpus()


@pytest.mark.parametrize("case", CASES, ids=[f"{c.file}:{c.id}" for c in CASES])
def test_corpus_entry(case: Case) -> None:
    verdict = validate(case.sql)

    if case.verdict == "allow":
        assert verdict.allowed, f"over-blocked: {verdict.reason}"
        assert verdict.reason is None
        return

    assert not verdict.allowed, "allowed an attack"
    assert verdict.reason is not None and case.reason is not None
    if ":" in case.reason:
        assert verdict.reason == case.reason
    else:
        assert verdict.reason.split(":", 1)[0] == case.reason


def test_corpus_is_well_formed() -> None:
    ids = [c.id for c in CASES]
    assert len(ids) == len(set(ids)), "duplicate corpus ids"
    for c in CASES:
        assert c.verdict in {"allow", "reject"}, c.id
        if c.verdict == "reject":
            assert c.reason, f"{c.id}: reject without a reason"
            assert c.reason.split(":", 1)[0] in REASON_CODES, c.id
            assert c.enforced_by is None, f"{c.id}: enforced_by only applies to allowed entries"
        else:
            assert c.reason is None, f"{c.id}: allowed entries have no reason"
        assert c.enforced_by in {None, "db"}, c.id


def test_corpus_is_not_trivially_small() -> None:
    assert sum(c.verdict == "reject" for c in CASES) >= 200
    assert sum(c.verdict == "allow" for c in CASES) >= 50
