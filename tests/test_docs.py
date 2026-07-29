"""Documentation parity.

Every published repository in this portfolio carries the same eight documents. A
reader who arrives at one of them should not have to discover that the
troubleshooting guide exists only in a different repository, and a contributor
should not have to guess where the trust boundary is written down.

These are shape checks, not prose reviews -- but a missing file and a stub file
both fail, because a heading with nothing under it is worse than an honest gap.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

REQUIRED = {
    "README.md": 2000,
    "SCOPE.md": 800,
    "CHANGELOG.md": 300,
    "SECURITY.md": 500,
    "CONTRIBUTING.md": 800,
    "ARCHITECTURE.md": 1200,
    "TROUBLESHOOTING.md": 1200,
    "CITATION.cff": 300,
}


@pytest.mark.parametrize("name", sorted(REQUIRED))
def test_the_document_exists_and_is_not_a_stub(name):
    path = ROOT / name
    assert path.is_file(), f"{name} is missing"
    assert len(path.read_text(encoding="utf-8")) >= REQUIRED[name], f"{name} is a stub"


def test_the_readme_links_the_portfolio_so_a_visitor_can_see_the_whole():
    """The gap a reader actually hits: nine repositories that look unrelated."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "certified-discovery" in text


def test_citation_metadata_is_parseable_and_points_at_this_repository():
    text = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    assert text.startswith("cff-version:")
    assert "repository-code:" in text
    assert "license: Apache-2.0" in text
    assert "certkit" in text, "the citation must name this repository"


def test_scope_says_what_the_tool_does_not_do():
    """A scope document that only lists features is marketing."""
    text = (ROOT / "SCOPE.md").read_text(encoding="utf-8").lower()
    assert "does not" in text or "not a" in text


def test_troubleshooting_is_keyed_to_real_messages():
    """Every heading should be something a user can paste from their terminal,
    not a topic. Checked loosely: at least one heading contains a code span or an
    error-shaped string."""
    text = (ROOT / "TROUBLESHOOTING.md").read_text(encoding="utf-8")
    headings = [line for line in text.splitlines() if line.startswith("## ")]
    assert len(headings) >= 5, "a troubleshooting guide with four entries is a FAQ"
    assert any("`" in h or "error" in h.lower() or ":" in h for h in headings)
