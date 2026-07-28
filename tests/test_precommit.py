"""The pre-commit hook.

The interesting cases are the ones where a gate is tempted to be helpful: a
certificate with no spec beside it, and an UNVERIFIED result. Both pass through a
naive hook as "nothing to report". Neither does here.
"""

from __future__ import annotations

import json

import pytest

from certkit.cli import _load, example_path
from certkit.precommit import main, spec_for

SPEC = _load(example_path("heartbleed.spec.json"))
GOOD = _load(example_path("heartbleed.cert.json"))
FORGED = _load(example_path("heartbleed.forged.json"))


def _pair(tmp_path, cert, name="guard"):
    spec_path = tmp_path / f"{name}.spec.json"
    cert_path = tmp_path / f"{name}.cert.json"
    spec_path.write_text(json.dumps(SPEC), encoding="utf-8")
    cert_path.write_text(json.dumps(cert), encoding="utf-8")
    return cert_path


def test_spec_for_pairs_by_convention(tmp_path):
    assert spec_for(tmp_path / "x.cert.json").name == "x.spec.json"


def test_a_valid_certificate_passes(tmp_path, capsys):
    cert = _pair(tmp_path, GOOD)
    assert main([str(cert)]) == 0
    assert "ACCEPTED" in capsys.readouterr().out


def test_a_forged_certificate_blocks_the_commit(tmp_path, capsys):
    cert = _pair(tmp_path, FORGED)
    assert main([str(cert)]) == 1
    err = capsys.readouterr().err
    assert "REFUSED" in err
    assert "obligation 0" in err


def test_a_certificate_with_no_spec_beside_it_fails_rather_than_skipping(tmp_path, capsys):
    """The failure mode this hook exists to avoid: a gate that reports success
    because it checked nothing."""
    orphan = tmp_path / "orphan.cert.json"
    orphan.write_text(json.dumps(GOOD), encoding="utf-8")
    assert main([str(orphan)]) == 1
    err = capsys.readouterr().err
    assert "no specification found" in err
    assert "orphan.spec.json" in err


def test_an_unbound_certificate_blocks_the_commit(tmp_path, capsys):
    """UNVERIFIED is exit 3 from the CLI; in a gate it must still block."""
    unbound = {k: v for k, v in GOOD.items() if k != "spec_fingerprint"}
    cert = _pair(tmp_path, unbound)
    assert main([str(cert)]) == 1
    assert "not bound" in capsys.readouterr().err


def test_unreadable_json_is_a_failure_not_a_crash(tmp_path, capsys):
    (tmp_path / "x.spec.json").write_text(json.dumps(SPEC), encoding="utf-8")
    bad = tmp_path / "x.cert.json"
    bad.write_text("{not json", encoding="utf-8")
    assert main([str(bad)]) == 1
    assert "FAIL" in capsys.readouterr().err


def test_no_staged_certificates_says_so(capsys):
    assert main([]) == 0
    assert "no certificates staged" in capsys.readouterr().out


def test_several_certificates_are_all_reported_not_just_the_first(tmp_path, capsys):
    good = _pair(tmp_path, GOOD, name="a")
    bad = _pair(tmp_path, FORGED, name="b")
    assert main([str(good), str(bad)]) == 1
    captured = capsys.readouterr()
    assert "a.cert.json: ACCEPTED" in captured.out
    assert "b.cert.json" in captured.err
    assert "1 certificate(s) did not verify" in captured.err


@pytest.mark.parametrize("template", ["gitlab-ci.yml", "circleci.yml"])
def test_ci_templates_treat_exit_3_as_a_failure(template):
    """The templates must not use a pattern that swallows a non-zero status."""
    from pathlib import Path

    text = (Path(__file__).resolve().parent.parent / "ci-templates" / template).read_text()
    assert "|| status=$?" in text, "a failing check must be recorded, not ignored"
    assert "exit $status" in text
    assert "|| true" not in text
