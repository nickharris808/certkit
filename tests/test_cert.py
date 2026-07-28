"""End-to-end certificate tests, including the reconstruction defence.

The test that matters most here is
``test_certificate_proving_an_unrelated_easy_system_is_rejected``: it is the one
that distinguishes this checker from a checker that simply trusts whatever atoms
the certificate hands it.
"""

import copy
import json

from certkit import atom, check_certificate, fingerprint, make_spec
from certkit.cert import CERT_SCHEMA, reconstruct_obligation


def heartbleed_spec():
    """0 <= p <= 65535 ; guard 19+p <= r ; safety 3+p <= r."""
    domain = [atom({"p": -1}), atom({"p": 1}, -65535)]
    guard = [atom({"p": 1, "r": -1}, 19)]
    safety = [atom({"p": 1, "r": -1}, 3)]
    return make_spec(domain, guard, safety, name="heartbleed")


def heartbleed_cert(spec):
    # Reconstructed atom order: domain(0,1), guard(2), NOT(safety)(3).
    return {
        "schema": CERT_SCHEMA,
        "spec_fingerprint": spec["fingerprint"],
        "obligations": [{"multipliers": {"2": 1, "3": 1}}],
    }


def test_valid_certificate_accepted():
    spec = heartbleed_spec()
    report = check_certificate(spec, heartbleed_cert(spec))
    assert report, report.reason
    assert len(report.obligations) == 1
    assert report.obligations[0]["ok"]


def test_reconstruction_uses_spec_not_cert():
    spec = heartbleed_spec()
    atoms = reconstruct_obligation({**spec, "safety_index": 0})
    # domain(2) + guard(1) + one negated safety conjunct(1)
    assert len(atoms) == 4
    assert atoms[3].strict is True  # negation of a non-strict atom is strict


def test_certificate_proving_an_unrelated_easy_system_is_rejected():
    """The core anti-forgery property.

    A forger supplies a certificate carrying its own trivially-refutable system
    plus valid multipliers for it. Because the checker rebuilds the obligation
    from the spec and ignores certificate-supplied atoms, the multipliers no
    longer refute anything and the certificate is refused.
    """
    spec = heartbleed_spec()
    forged = {
        "schema": CERT_SCHEMA,
        "spec_fingerprint": spec["fingerprint"],
        # An easy system the forger *can* refute, smuggled in alongside.
        "atoms": [
            {"coeff": {"z": [1, 1]}, "const": [1, 1], "strict": False},
            {"coeff": {"z": [-1, 1]}, "const": [1, 1], "strict": False},
        ],
        "obligations": [{"multipliers": {"0": 1, "1": 1}}],
    }
    report = check_certificate(spec, forged)
    assert not report
    # Multipliers 0 and 1 hit the two *domain* atoms, which do not cancel.
    assert not report.obligations[0]["ok"]


def test_certificate_bound_to_a_different_spec_is_rejected():
    spec = heartbleed_spec()
    cert = heartbleed_cert(spec)
    cert["spec_fingerprint"] = "0" * 64
    report = check_certificate(spec, cert)
    assert not report
    assert "different spec" in report.reason


def test_unbound_certificate_is_rejected():
    spec = heartbleed_spec()
    cert = heartbleed_cert(spec)
    del cert["spec_fingerprint"]
    report = check_certificate(spec, cert)
    assert not report
    assert "not bound" in report.reason


def test_tampered_spec_body_is_detected():
    """Editing the spec without recomputing its fingerprint is caught."""
    spec = heartbleed_spec()
    tampered = copy.deepcopy(spec)
    # Weaken the guard from 19 to 3 -- the property would become trivial.
    tampered["guard"][0]["const"] = [3, 1]
    report = check_certificate(tampered, heartbleed_cert(spec))
    assert not report
    assert "fingerprint" in report.reason


def test_wrong_schema_rejected():
    spec = heartbleed_spec()
    cert = heartbleed_cert(spec)
    cert["schema"] = "something/else/v9"
    assert not check_certificate(spec, cert)


def test_obligation_count_must_match():
    spec = heartbleed_spec()
    cert = heartbleed_cert(spec)
    cert["obligations"] = []
    report = check_certificate(spec, cert)
    assert not report
    assert "obligation" in report.reason


def test_missing_multipliers_rejected():
    spec = heartbleed_spec()
    cert = heartbleed_cert(spec)
    cert["obligations"] = [{}]
    report = check_certificate(spec, cert)
    assert not report


def test_multi_conjunct_safety_requires_all_obligations():
    """Two safety conjuncts: refuting only one is not enough."""
    domain = [atom({"p": -1}), atom({"p": 1}, -100)]
    guard = [atom({"p": 1, "r": -1}, 19)]
    safety = [atom({"p": 1, "r": -1}, 3), atom({"p": 1, "r": -1}, 5)]
    spec = make_spec(domain, guard, safety, name="two-conjunct")

    good = {
        "schema": CERT_SCHEMA,
        "spec_fingerprint": spec["fingerprint"],
        "obligations": [{"multipliers": {"2": 1, "3": 1}}, {"multipliers": {"2": 1, "3": 1}}],
    }
    assert check_certificate(spec, good)

    half = copy.deepcopy(good)
    half["obligations"][1] = {"multipliers": {"0": 1}}
    report = check_certificate(spec, half)
    assert not report
    assert report.obligations[0]["ok"]
    assert not report.obligations[1]["ok"]


def test_spec_and_cert_survive_json_roundtrip():
    spec = heartbleed_spec()
    cert = heartbleed_cert(spec)
    spec2 = json.loads(json.dumps(spec))
    cert2 = json.loads(json.dumps(cert))
    assert check_certificate(spec2, cert2)


def test_fingerprint_is_order_independent():
    a = {"schema": "x", "b": 1, "a": 2}
    b = {"a": 2, "schema": "x", "b": 1}
    assert fingerprint(a) == fingerprint(b)
