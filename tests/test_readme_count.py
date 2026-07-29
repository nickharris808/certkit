"""The README's test count must be the number of tests there are.

Every README in this portfolio quotes a test count, and every one of them was
wrong by the time anyone read it -- certkit said 174 when it had 540. A number a
reader can check in one command, and which is false, is worse than no number:
it teaches them not to trust the others.

So the count is checked here. `pytest --collect-only` in a subprocess counts the
suite; the README must agree. Collection does not execute anything, so this
cannot recurse.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def collected_count() -> int:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    match = re.search(r"(\d+) tests? collected", result.stdout)
    assert match, f"could not read a collection count from:\n{result.stdout[-800:]}"
    return int(match.group(1))


def readme_count() -> int:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(r"\*?\*?(\d[\d,]*)\*?\*? tests\b", text)
    assert match, "the README does not state a test count"
    return int(match.group(1).replace(",", ""))


def test_the_readme_states_the_real_test_count():
    stated = readme_count()
    actual = collected_count()
    assert stated == actual, (
        f"the README says {stated} tests; the suite collects {actual}. "
        "Update the README rather than this test -- the number is the claim."
    )
