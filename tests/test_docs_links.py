"""Every relative link in the docs points at a file that exists."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DOCS = [REPO / "README.md", REPO / "CLAUDE.md", *sorted((REPO / "docs").rglob("*.md"))]
LINK = re.compile(r"\]\(([^)\s]+)\)")


def _relative_links(path: Path) -> list[str]:
    links = []
    for target in LINK.findall(path.read_text(encoding="utf-8")):
        if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
            continue  # URLs, mailto:, same-page anchors
        links.append(target.split("#", 1)[0])
    return links


@pytest.mark.parametrize("doc", DOCS, ids=[str(d.relative_to(REPO)) for d in DOCS])
def test_relative_links_resolve(doc: Path) -> None:
    missing = [t for t in _relative_links(doc) if not (doc.parent / t).exists()]
    assert missing == [], f"{doc.relative_to(REPO)}: missing {missing}"


def test_the_threat_model_links_real_tests() -> None:
    links = _relative_links(REPO / "docs" / "threat-model.md")
    assert sum("tests/" in link for link in links) >= 20
