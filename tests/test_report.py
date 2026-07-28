"""Output formats: every projection must state the same verdict.

The risk with multiple emitters is drift -- a refusal worded one way in the log
and another in the Security tab, or worse, a format that renders UNVERIFIED as a
pass. These tests assert that every format carries the verdict the report
actually holds.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

import pytest

from certkit import ACCEPTED, REFUSED, UNVERIFIED, atom, check_certificate, make_spec
from certkit.cli import main as cli_main
from certkit.report import FORMATS, render

DOMAIN = [atom({"payload": -1}), atom({"payload": 1}, -65535)]
GUARD = [atom({"payload": 1, "record_len": -1}, 19)]
SAFETY = [atom({"payload": 1, "record_len": -1}, 3)]
SPEC = make_spec(DOMAIN, GUARD, SAFETY, name="heartbleed")
GOOD = {
    "schema": "certkit/farkas/v1",
    "spec_fingerprint": SPEC["fingerprint"],
    "obligations": [{"multipliers": {"2": 1, "3": 1}}],
}
FORGED = {
    "schema": "certkit/farkas/v1",
    "spec_fingerprint": SPEC["fingerprint"],
    "obligations": [{"multipliers": {"0": 1, "1": 1}}],
}

ACCEPTED_REPORT = check_certificate(SPEC, GOOD)
REFUSED_REPORT = check_certificate(SPEC, FORGED)
UNVERIFIED_REPORT = check_certificate(SPEC, GOOD, require_fingerprint=False)


@pytest.mark.parametrize("fmt", FORMATS)
def test_every_format_renders_every_verdict(fmt):
    for report in (ACCEPTED_REPORT, REFUSED_REPORT, UNVERIFIED_REPORT):
        out = render(report, fmt, name="heartbleed")
        assert isinstance(out, str) and out.strip()


def test_unknown_format_raises_rather_than_guessing():
    with pytest.raises(ValueError) as exc:
        render(ACCEPTED_REPORT, "yaml")
    assert "unknown format" in str(exc.value)


# --------------------------------------------------------------------------- #
# UNVERIFIED must never render as a pass, in any format
# --------------------------------------------------------------------------- #


def test_json_carries_the_three_way_verdict():
    for report, expected in (
        (ACCEPTED_REPORT, ACCEPTED),
        (REFUSED_REPORT, REFUSED),
        (UNVERIFIED_REPORT, UNVERIFIED),
    ):
        payload = json.loads(render(report, "json"))
        assert payload["verdict"] == expected
        assert payload["ok"] is (expected == ACCEPTED)


def test_junit_marks_unverified_as_a_failure_with_its_own_type():
    root = ET.fromstring(render(UNVERIFIED_REPORT, "junit", name="hb"))
    assert root.get("failures") == "1"
    failure = root.find(".//failure")
    assert failure is not None
    assert failure.get("type") == "unverified"


def test_junit_distinguishes_refused_from_unverified():
    assert (
        ET.fromstring(render(REFUSED_REPORT, "junit")).find(".//failure").get("type") == "refused"
    )
    assert ET.fromstring(render(ACCEPTED_REPORT, "junit")).find(".//failure") is None


def test_junit_is_well_formed_xml_for_every_verdict():
    for report in (ACCEPTED_REPORT, REFUSED_REPORT, UNVERIFIED_REPORT):
        ET.fromstring(render(report, "junit", name='weird "name" & <chars>'))


def test_sarif_emits_a_finding_only_for_a_non_pass():
    assert json.loads(render(ACCEPTED_REPORT, "sarif"))["runs"][0]["results"] == []
    for report in (REFUSED_REPORT, UNVERIFIED_REPORT):
        results = json.loads(render(report, "sarif", name="a/b.spec.json"))["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["level"] == "error"
        assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
            "a/b.spec.json"
        )


def test_sarif_rule_ids_are_all_declared():
    doc = json.loads(render(UNVERIFIED_REPORT, "sarif", name="x"))
    run = doc["runs"][0]
    declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in run["results"]} <= declared


def test_sarif_uses_the_unverified_rule_for_unverified():
    doc = json.loads(render(UNVERIFIED_REPORT, "sarif", name="x"))
    assert doc["runs"][0]["results"][0]["ruleId"] == "certkit/unverified"


def test_markdown_bolds_a_non_pass():
    assert "**REFUSED**" in render(REFUSED_REPORT, "markdown")
    assert "**UNVERIFIED**" in render(UNVERIFIED_REPORT, "markdown")
    assert "**" not in render(ACCEPTED_REPORT, "markdown").split("|")[2]


# --------------------------------------------------------------------------- #
# the CLI wiring
# --------------------------------------------------------------------------- #


def _write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


@pytest.mark.parametrize("fmt", FORMATS)
def test_cli_format_flag_preserves_the_exit_code(tmp_path, fmt, capsys):
    """Changing the output format must never change the verdict."""
    s = _write(tmp_path, "s.json", SPEC)
    assert (
        cli_main(
            ["check", "--spec", s, "--cert", _write(tmp_path, "g.json", GOOD), "--format", fmt]
        )
        == 0
    )
    capsys.readouterr()
    assert (
        cli_main(
            ["check", "--spec", s, "--cert", _write(tmp_path, "f.json", FORGED), "--format", fmt]
        )
        == 1
    )
    capsys.readouterr()
    assert (
        cli_main(
            [
                "check",
                "--spec",
                s,
                "--cert",
                _write(tmp_path, "g2.json", GOOD),
                "--format",
                fmt,
                "--no-fingerprint",
            ]
        )
        == 3
    )


def test_cli_json_flag_is_shorthand_for_format_json(tmp_path, capsys):
    s = _write(tmp_path, "s.json", SPEC)
    c = _write(tmp_path, "c.json", GOOD)
    cli_main(["check", "--spec", s, "--cert", c, "--json"])
    a = capsys.readouterr().out
    cli_main(["check", "--spec", s, "--cert", c, "--format", "json"])
    assert json.loads(a) == json.loads(capsys.readouterr().out)


def test_cli_schema_command_prints_valid_json(capsys):
    assert cli_main(["schema", "--format", "certkit/spec/v1"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["title"].startswith("certkit specification")
