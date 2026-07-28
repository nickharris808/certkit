"""Adversarial regression suite.

The oracle for every test in this file is one sentence:

    **No input may produce a confident-looking answer that is wrong.**

For a proof checker, the confident-looking answer is ``ACCEPTED``. The tests
below try to obtain one without earning it: by forging a certificate, by
removing the trust anchor, by cross-applying a valid proof to a different spec,
and by feeding the checker input no honest producer would emit.

The headline regression is the trust-anchor case. ``require_fingerprint=False``
used to report ``ok=True`` for a certificate that had never been bound to the
spec -- a pass on input the checker had not fully validated.
"""

from __future__ import annotations

import json

import pytest

from certkit import (
    ACCEPTED,
    REFUSED,
    UNVERIFIED,
    atom,
    check_certificate,
    make_spec,
    verify_farkas,
)
from certkit.cert import reconstruct_obligation
from certkit.cli import main as cli_main

# The Heartbleed shape: 19 + p <= r implies 3 + p <= r for p in [0, 65535].
DOMAIN = [atom({"payload": -1}), atom({"payload": 1}, -65535)]
GUARD = [atom({"payload": 1, "record_len": -1}, 19)]
SAFETY = [atom({"payload": 1, "record_len": -1}, 3)]
SPEC = make_spec(DOMAIN, GUARD, SAFETY, name="heartbleed")
GOOD = {
    "schema": "certkit/farkas/v1",
    "spec_fingerprint": SPEC["fingerprint"],
    "obligations": [{"multipliers": {"2": 1, "3": 1}}],
}


def _cert(multipliers, fingerprint=SPEC["fingerprint"]):
    return {
        "schema": "certkit/farkas/v1",
        "spec_fingerprint": fingerprint,
        "obligations": [{"multipliers": multipliers}],
    }


# --------------------------------------------------------------------------- #
# the trust anchor -- a missing precondition must be loud
# --------------------------------------------------------------------------- #


def test_baseline_valid_certificate_is_accepted():
    report = check_certificate(SPEC, GOOD)
    assert report.verdict == ACCEPTED
    assert report.ok is True
    assert report.binding_verified is True


def test_no_fingerprint_can_never_accept():
    """The arithmetic checks out, but nothing bound it to this spec.

    This used to report ``ok=True`` and print ACCEPTED.
    """
    report = check_certificate(SPEC, GOOD, require_fingerprint=False)
    assert report.obligations_ok is True  # the multipliers really do refute it
    assert report.binding_verified is False
    assert report.verdict == UNVERIFIED
    assert report.ok is False
    assert bool(report) is False


def test_missing_precondition_is_stated_in_the_reason():
    report = check_certificate(SPEC, GOOD, require_fingerprint=False)
    assert "TRUST ANCHOR ABSENT" in report.reason
    assert "Not an acceptance" in report.reason


def test_unverified_is_visible_in_the_serialised_form():
    """An automated consumer reading JSON must see it too, not just a human."""
    d = check_certificate(SPEC, GOOD, require_fingerprint=False).to_dict()
    assert d["verdict"] == UNVERIFIED
    assert d["ok"] is False
    assert d["binding_verified"] is False


def test_unbound_certificate_is_refused_when_the_anchor_is_required():
    unbound = {"schema": "certkit/farkas/v1", "obligations": [{"multipliers": {"2": 1, "3": 1}}]}
    report = check_certificate(SPEC, unbound)
    assert report.verdict == REFUSED
    assert "not bound" in report.reason


def test_certificate_bound_to_a_different_spec_is_refused():
    report = check_certificate(SPEC, _cert({"2": 1, "3": 1}, fingerprint="0" * 64))
    assert report.verdict == REFUSED
    assert "different spec" in report.reason


def test_tampered_spec_body_is_refused():
    tampered = dict(SPEC)
    tampered["guard"] = [
        {"coeff": {"payload": [1, 1], "record_len": [-1, 1]}, "const": [1, 1], "strict": False}
    ]
    report = check_certificate(tampered, GOOD)
    assert report.verdict == REFUSED
    assert "does not match its own body" in report.reason


# --------------------------------------------------------------------------- #
# cross-application: a valid proof of something else must not transfer
# --------------------------------------------------------------------------- #


def test_valid_proof_of_another_system_does_not_transfer_even_unanchored():
    """The reconstruction defence, tested with the anchor removed.

    With ``require_fingerprint=False`` the fingerprint cannot catch this, so the
    only thing standing between the forger and an acceptance is that the checker
    rebuilds the obligation from the spec. It must still refuse.
    """
    unsound = make_spec(DOMAIN, [atom({"payload": 1, "record_len": -1}, 1)], SAFETY, name="weak")
    report = check_certificate(unsound, GOOD, require_fingerprint=False)
    assert report.verdict == REFUSED
    assert report.ok is False


def test_certificate_carrying_its_own_easy_system_is_ignored():
    forged = dict(GOOD)
    forged["atoms"] = [{"coeff": {"z": [1, 1]}, "const": [1, 1], "strict": False}]
    forged["obligations"] = [{"multipliers": {"0": 1}, "atoms": forged["atoms"]}]
    report = check_certificate(SPEC, forged)
    assert report.verdict == REFUSED


# --------------------------------------------------------------------------- #
# malformed input -- reject, never raise
# --------------------------------------------------------------------------- #

MALFORMED_MULTIPLIERS = [
    {},  # empty
    {"0": 0, "1": 0},  # all zero
    {"2": -1, "3": 1},  # negative weight
    {"2": 1, "999": 1},  # index out of range
    {"nope": 1},  # non-integer index
    {"2": "banana"},  # unparseable weight
    {"2": None},  # null weight
    {"2": True},  # bool is not a multiplier
    {"2": [1, 0]},  # zero denominator
    {"2": float("nan"), "3": 1},  # NaN
    {"2": float("inf"), "3": 1},  # Infinity
    {"2": {"nested": 1}},  # wrong container
]


@pytest.mark.parametrize("multipliers", MALFORMED_MULTIPLIERS)
def test_malformed_multipliers_are_refused_not_raised(multipliers):
    report = check_certificate(SPEC, _cert(multipliers))
    assert report.verdict == REFUSED
    assert report.ok is False


MALFORMED_CERTS = [
    {},
    {"schema": "certkit/farkas/v1"},
    {"schema": "wrong/schema", "obligations": []},
    {"schema": "certkit/farkas/v1", "spec_fingerprint": SPEC["fingerprint"], "obligations": {}},
    {"schema": "certkit/farkas/v1", "spec_fingerprint": SPEC["fingerprint"], "obligations": []},
    {
        "schema": "certkit/farkas/v1",
        "spec_fingerprint": SPEC["fingerprint"],
        "obligations": [{"multipliers": None}],
    },
    {
        "schema": "certkit/farkas/v1",
        "spec_fingerprint": SPEC["fingerprint"],
        "obligations": ["not-an-object"],
    },
]


@pytest.mark.parametrize("cert", MALFORMED_CERTS)
def test_malformed_certificates_are_refused_not_raised(cert):
    assert check_certificate(SPEC, cert).ok is False


MALFORMED_SPECS = [
    {},
    {"schema": "certkit/spec/v1"},
    {"schema": "certkit/spec/v1", "safety": []},
    {"schema": "nope/v1", "safety": [{"coeff": {}}]},
]


@pytest.mark.parametrize("spec", MALFORMED_SPECS)
def test_malformed_specs_are_refused_not_raised(spec):
    assert check_certificate(spec, GOOD).ok is False


# A spec is attacker-controlled input too. These all used to escape as raw
# ZeroDivisionError / TypeError / AttributeError tracebacks, which contradicts
# the documented rule "reject, don't raise".
MALFORMED_ATOMS = [
    {"coeff": {"x": [1, 0]}, "const": [1, 1]},  # zero denominator in a coefficient
    {"coeff": {"x": [1, 1]}, "const": [1, 0]},  # zero denominator in the constant
    {"coeff": {"x": float("inf")}},  # Infinity
    {"coeff": {"x": float("nan")}},  # NaN
    {"coeff": {"x": "abc"}},  # unparseable
    {"coeff": {"x": None}},  # null
    {"coeff": [1, 2]},  # coeff is not a mapping
    "not-a-dict",  # the atom is not an object
]


@pytest.mark.parametrize("slot", ["domain", "guard", "safety"])
@pytest.mark.parametrize("bad_atom", MALFORMED_ATOMS)
def test_malformed_spec_atoms_are_refused_not_raised(slot, bad_atom):
    spec = {
        "schema": "certkit/spec/v1",
        "name": "t",
        "domain": [],
        "guard": [],
        "safety": [{"coeff": {"x": [1, 1]}}],
    }
    spec[slot] = [bad_atom]
    cert = {"schema": "certkit/farkas/v1", "obligations": [{"multipliers": {"0": 1}}]}
    report = check_certificate(spec, cert, require_fingerprint=False)
    assert report.verdict == REFUSED
    assert report.ok is False


@pytest.mark.parametrize("safety", ["string", 42, {"a": 1}, None])
def test_non_list_safety_is_refused_not_raised(safety):
    spec = {"schema": "certkit/spec/v1", "domain": [], "guard": [], "safety": safety}
    assert check_certificate(spec, GOOD).ok is False


def test_duplicate_json_keys_do_not_smuggle_a_second_verdict():
    """Last-wins is Python's rule; the point is that it is deterministic and refused."""
    raw = '{"schema":"certkit/farkas/v1","spec_fingerprint":"%s","obligations":[{"multipliers":{"2":1,"3":1}}],"obligations":[{"multipliers":{"0":1}}]}'
    cert = json.loads(raw % SPEC["fingerprint"])
    assert check_certificate(SPEC, cert).ok is False


# --------------------------------------------------------------------------- #
# enormous
# --------------------------------------------------------------------------- #


def test_astronomically_large_multipliers_are_handled_exactly():
    """Exact rationals, so a 10^400 weight is arithmetic, not overflow."""
    k = 10**400
    report = check_certificate(SPEC, _cert({"2": k, "3": k}))
    assert report.verdict == ACCEPTED


def test_many_obligations_does_not_hang_or_accept():
    big = {"schema": "certkit/farkas/v1", "spec_fingerprint": SPEC["fingerprint"]}
    big["obligations"] = [{"multipliers": {"2": 1, "3": 1}}] * 5000
    assert check_certificate(SPEC, big).ok is False  # count mismatch vs. one conjunct


def test_deeply_nested_value_is_refused_not_raised():
    nested = {"a": 1}
    for _ in range(200):
        nested = {"a": nested}
    assert check_certificate(SPEC, _cert({"2": nested})).ok is False


@pytest.mark.parametrize("key", ["__proto__", "__class__", "constructor"])
def test_hostile_keys_are_inert(key):
    cert = _cert({"2": 1, "3": 1})
    cert[key] = {"schema": "certkit/farkas/v1"}
    assert check_certificate(SPEC, cert).verdict == ACCEPTED  # extra keys are ignored


# --------------------------------------------------------------------------- #
# metamorphic
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("k", [1, 2, 7, 10**12])
def test_scaling_every_multiplier_preserves_validity(k):
    """A Farkas certificate is a ray: positive scaling cannot change its verdict."""
    assert check_certificate(SPEC, _cert({"2": k, "3": k})).verdict == ACCEPTED


def test_scaling_by_zero_destroys_validity():
    assert check_certificate(SPEC, _cert({"2": 0, "3": 0})).verdict == REFUSED


def test_rational_string_and_pair_forms_agree():
    a = check_certificate(SPEC, _cert({"2": "1/3", "3": "1/3"}))
    b = check_certificate(SPEC, _cert({"2": [1, 3], "3": [1, 3]}))
    assert a.verdict == b.verdict == ACCEPTED


def test_reconstruction_is_order_stable():
    """domain ++ guard ++ [not safety[i]] -- the indices a certificate refers to."""
    body = {k: v for k, v in SPEC.items() if k != "fingerprint"}
    body["safety_index"] = 0
    atoms = reconstruct_obligation(body)
    assert len(atoms) == 4
    assert verify_farkas(atoms, {"2": 1, "3": 1}).ok is True


# --------------------------------------------------------------------------- #
# the CLI contract -- exit codes are what CI actually reads
# --------------------------------------------------------------------------- #


def _write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


def test_cli_exit_code_zero_only_for_a_bound_valid_certificate(tmp_path):
    spec_p = _write(tmp_path, "s.json", SPEC)
    cert_p = _write(tmp_path, "c.json", GOOD)
    assert cli_main(["check", "--spec", spec_p, "--cert", cert_p]) == 0


def test_cli_exit_code_three_for_unverified(tmp_path, capsys):
    """--no-fingerprint must not exit 0. CI would read that as a pass."""
    spec_p = _write(tmp_path, "s.json", SPEC)
    cert_p = _write(tmp_path, "c.json", GOOD)
    code = cli_main(["check", "--spec", spec_p, "--cert", cert_p, "--no-fingerprint"])
    assert code == 3
    out = capsys.readouterr().out
    # The verdict line is what a skim-reader sees; it must not say ACCEPTED.
    # (The body may mention ACCEPTED while explaining that this is not one.)
    verdict_line = out.splitlines()[0]
    assert verdict_line.startswith("UNVERIFIED:")
    assert "TRUST ANCHOR ABSENT" in out


def test_cli_exit_code_one_for_a_refusal(tmp_path):
    spec_p = _write(tmp_path, "s.json", SPEC)
    cert_p = _write(tmp_path, "c.json", _cert({"0": 1, "1": 1}))
    assert cli_main(["check", "--spec", spec_p, "--cert", cert_p]) == 1
