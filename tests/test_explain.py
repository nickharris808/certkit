"""Tests for `certkit explain`.

Explaining is not deciding. The risk in a prose renderer is that it tells a
reassuring story the checker does not support -- so the tests here are mostly
about the explanation *agreeing with the verdict*, especially when the verdict
is negative.
"""

from __future__ import annotations

import json

import pytest

from certkit import atom, make_spec
from certkit.cli import example_path
from certkit.cli import main as cli_main
from certkit.explain import explain_certificate, explain_obligation, format_atom
from certkit.scaffold import parse_relation

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


# --------------------------------------------------------------------------- #
# atom rendering
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "text,rendered",
    [
        ("19 + payload <= record_len", "payload - record_len + 19 <= 0"),
        ("0 <= payload", "-payload <= 0"),
        ("n > 0", "-n < 0"),
        # Terms are emitted in alphabetical order: len, offset, size.
        ("2*offset + len < size", "len + 2*offset - size < 0"),
    ],
)
def test_format_atom_reads_as_the_inequality_it_means(text, rendered):
    assert format_atom(parse_relation(text)) == rendered


# --------------------------------------------------------------------------- #
# the explanation must match the verdict
# --------------------------------------------------------------------------- #


def test_explanation_shows_the_actual_arithmetic():
    out = explain_certificate(SPEC, GOOD)
    assert "payload - record_len + 19 <= 0" in out  # the guard atom
    assert "-payload + record_len - 3 < 0" in out  # the negated safety atom
    assert "Every variable cancels" in out
    assert "16 < 0" in out  # the surviving contradiction, computed not asserted
    assert "no solution" in out


def test_explanation_of_a_forgery_does_not_claim_a_proof():
    out = explain_certificate(SPEC, FORGED)
    assert "do NOT refute" in out
    assert "no solution" not in out
    # And it must not leave the reader thinking a refusal is a disproof.
    assert "not proven" in out
    assert "never certifies the negation" in out


def test_explanation_never_says_proved_when_the_checker_refuses():
    """Sweep hostile multipliers: no explanation may claim a proof."""
    for multipliers in ({}, {"0": 1}, {"2": -1}, {"9": 1}, {"2": 0, "3": 0}):
        cert = dict(GOOD, obligations=[{"multipliers": multipliers}])
        out = explain_certificate(SPEC, cert)
        assert "no solution" not in out, multipliers


def test_explanation_handles_a_missing_multiplier_block():
    out = explain_certificate(SPEC, {"schema": "certkit/farkas/v1", "obligations": []})
    assert "supplies no multipliers" in out


def test_explanation_handles_a_malformed_spec_without_raising():
    bad = {"schema": "certkit/spec/v1", "safety": [{"coeff": {"x": [1, 0]}}]}
    out = explain_certificate(bad, GOOD)
    assert "cannot be rebuilt" in out


def test_explanation_of_a_spec_with_no_safety():
    out = explain_certificate({"schema": "certkit/spec/v1", "safety": []}, GOOD)
    assert "nothing to prove" in out


def test_multi_conjunct_spec_explains_every_obligation():
    safety = [
        atom({"payload": 1, "record_len": -1}, 3),
        atom({"payload": -1}, 0),
    ]
    spec = make_spec(DOMAIN, GUARD, safety, name="two")
    cert = {
        "schema": "certkit/farkas/v1",
        "spec_fingerprint": spec["fingerprint"],
        "obligations": [{"multipliers": {"2": 1, "3": 1}}, {"multipliers": {"0": 1, "3": 1}}],
    }
    out = explain_certificate(spec, cert)
    assert "Obligation 0" in out
    assert "Obligation 1" in out


def test_explain_obligation_reports_the_checker_reason_verbatim():
    from certkit.cert import reconstruct_obligation

    body = {k: v for k, v in SPEC.items() if k != "fingerprint"}
    body["safety_index"] = 0
    atoms = reconstruct_obligation(body)
    out = explain_obligation(atoms, {"0": 1, "1": 1}, index=0)
    assert "non-strict combination needs const > 0" in out


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


def test_cli_explain_exits_zero_on_a_valid_pair(tmp_path, capsys):
    code = cli_main(
        [
            "explain",
            "--spec",
            _write(tmp_path, "s.json", SPEC),
            "--cert",
            _write(tmp_path, "c.json", GOOD),
        ]
    )
    assert code == 0
    assert "Every variable cancels" in capsys.readouterr().out


def test_cli_explain_exit_status_tracks_the_verdict(tmp_path):
    """Explaining must not launder a refusal into a success exit code."""
    code = cli_main(
        [
            "explain",
            "--spec",
            _write(tmp_path, "s.json", SPEC),
            "--cert",
            _write(tmp_path, "c.json", FORGED),
        ]
    )
    assert code == 1


def test_cli_explain_on_the_bundled_example(capsys):
    code = cli_main(
        [
            "explain",
            "--spec",
            str(example_path("heartbleed.spec.json")),
            "--cert",
            str(example_path("heartbleed.cert.json")),
        ]
    )
    assert code == 0
    assert "16 < 0" in capsys.readouterr().out
