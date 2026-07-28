"""Notebook rendering.

A notebook is where a verdict is most likely to be skimmed rather than read, so
this is the surface where a friendly-looking summary does the most damage. The
tests below are about meaning, not appearance: whatever the HTML looks like, an
UNVERIFIED result must not read as a pass, and a hostile spec name must not
become markup.
"""

from __future__ import annotations

import pytest

from certkit import ACCEPTED, REFUSED, UNVERIFIED, check_certificate
from certkit.cli import _load, example_path
from certkit.notebook import COLOURS, report_html

SPEC = _load(example_path("heartbleed.spec.json"))
GOOD = _load(example_path("heartbleed.cert.json"))
FORGED = _load(example_path("heartbleed.forged.json"))


def test_accepted_renders_its_verdict():
    html = check_certificate(SPEC, GOOD)._repr_html_()
    assert ACCEPTED in html
    assert REFUSED not in html


def test_refused_renders_the_reason_and_never_says_accepted():
    html = check_certificate(SPEC, FORGED)._repr_html_()
    assert REFUSED in html
    assert ACCEPTED not in html
    assert "not a proof" in html.lower()


def test_unverified_is_not_dressed_up_as_either_other_verdict():
    report = check_certificate(SPEC, GOOD, require_fingerprint=False)
    html = report._repr_html_()
    assert UNVERIFIED in html
    assert ACCEPTED not in html
    assert "not a pass" in html.lower()


def test_unverified_gets_its_own_colour():
    """Not a shade of the acceptance colour and not a shade of the refusal one."""
    assert len({COLOURS[v] for v in (ACCEPTED, REFUSED, UNVERIFIED)}) == 3
    assert COLOURS[UNVERIFIED] != COLOURS[ACCEPTED]
    assert COLOURS[UNVERIFIED] != COLOURS[REFUSED]


@pytest.mark.parametrize(
    "name",
    ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>', "a&b<c"],
)
def test_a_hostile_spec_name_cannot_inject_markup(name):
    report = check_certificate(SPEC, GOOD)
    html = report_html(report, name=name)
    # The check is that no *tag* survives, not that the characters are absent:
    # escaped text is exactly what should be there.
    assert "<script>" not in html
    assert "<img" not in html
    assert "&lt;" in html or "&amp;" in html


def test_a_hostile_refusal_reason_is_escaped_too():
    """The reason string can contain spec-derived text."""
    spec = dict(SPEC)
    spec["safety"] = "<script>"
    html = check_certificate(spec, GOOD)._repr_html_()
    assert "<script>" not in html


def test_render_does_not_raise_on_an_empty_report():
    report = check_certificate({"schema": "wrong"}, GOOD)
    assert isinstance(report._repr_html_(), str)
