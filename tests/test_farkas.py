"""Farkas checker tests.

The negative cases matter more than the positive ones. A checker that accepts a
valid certificate is table stakes; a checker that *rejects* malformed, hostile,
and near-miss certificates is the actual product.
"""

from fractions import Fraction

import pytest

from certkit import atom, negate, verify_farkas

# --------------------------------------------------------------------------- #
# positive: genuinely infeasible systems
# --------------------------------------------------------------------------- #


def test_simple_contradiction():
    # x <= -1  and  -x <= -1   =>  add with weight 1 each  =>  0 <= -2, absurd.
    atoms = [atom({"x": 1}, 1), atom({"x": -1}, 1)]
    assert verify_farkas(atoms, {0: 1, 1: 1})


def test_strict_contradiction_allows_zero_constant():
    # x < 0 and -x <= 0  =>  sum is 0 < 0, which is false. const == 0 suffices
    # because the combination inherits strictness.
    atoms = [atom({"x": 1}, 0, strict=True), atom({"x": -1}, 0)]
    res = verify_farkas(atoms, {0: 1, 1: 1})
    assert res, res.reason


def test_rational_multipliers():
    # 2x <= -1 and -3x <= -1. Weights 3/2 and 1 cancel x: 0 <= -5/2.
    atoms = [atom({"x": 2}, 1), atom({"x": -3}, 1)]
    assert verify_farkas(atoms, {0: "3/2", 1: 1})


def test_heartbleed_shaped_obligation():
    # domain: 0 <= p <= 65535 ; guard: 19 + p <= r ; safety: 3 + p <= r
    # obligation = domain AND guard AND NOT(safety)
    domain = [atom({"p": -1}), atom({"p": 1}, -65535)]
    guard = [atom({"p": 1, "r": -1}, 19)]
    not_safe = negate(atom({"p": 1, "r": -1}, 3))
    atoms = domain + guard + [not_safe]
    # guard says p - r + 19 <= 0; negated safety says -p + r - 3 < 0.
    # Adding them: 16 <= 0 (strict), a contradiction.
    assert verify_farkas(atoms, {2: 1, 3: 1})


# --------------------------------------------------------------------------- #
# negative: the certificate does not prove the thing
# --------------------------------------------------------------------------- #


def test_variables_must_cancel():
    atoms = [atom({"x": 1}, 1), atom({"y": -1}, 1)]
    res = verify_farkas(atoms, {0: 1, 1: 1})
    assert not res
    assert "did not cancel" in res.reason


def test_feasible_system_is_rejected():
    # x <= 5 and x >= 0 is satisfiable; no multiplier vector can refute it.
    atoms = [atom({"x": 1}, -5), atom({"x": -1}, 0)]
    res = verify_farkas(atoms, {0: 1, 1: 1})
    assert not res


def test_negative_multiplier_rejected():
    atoms = [atom({"x": 1}, 1), atom({"x": -1}, 1)]
    res = verify_farkas(atoms, {0: 1, 1: -1})
    assert not res
    assert "negative multiplier" in res.reason


def test_all_zero_multipliers_rejected():
    atoms = [atom({"x": 1}, 1), atom({"x": -1}, 1)]
    res = verify_farkas(atoms, {0: 0, 1: 0})
    assert not res
    assert "all multipliers zero" in res.reason


def test_empty_multipliers_rejected():
    res = verify_farkas([atom({"x": 1}, 1)], {})
    assert not res


def test_non_strict_needs_positive_constant():
    # x <= 0 and -x <= 0 sum to 0 <= 0, which is satisfiable -- not a refutation.
    atoms = [atom({"x": 1}, 0), atom({"x": -1}, 0)]
    res = verify_farkas(atoms, {0: 1, 1: 1})
    assert not res
    assert "const > 0" in res.reason


# --------------------------------------------------------------------------- #
# hostile input: must reject, must not raise
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "multipliers",
    [
        {99: 1},  # index past the end
        {-1: 1},  # negative index
        {"nope": 1},  # non-integer index
        {0: "not-a-number"},  # unparseable weight
        {0: [1, 0]},  # zero denominator
        {0: None},  # wrong type
        {0: True},  # bool is not a multiplier
    ],
)
def test_hostile_input_is_rejected_not_raised(multipliers):
    atoms = [atom({"x": 1}, 1), atom({"x": -1}, 1)]
    res = verify_farkas(atoms, multipliers)
    assert not res
    assert res.reason


def test_string_indices_are_accepted():
    # JSON object keys are strings; a certificate loaded from disk must still work.
    atoms = [atom({"x": 1}, 1), atom({"x": -1}, 1)]
    assert verify_farkas(atoms, {"0": 1, "1": 1})


def test_float_multiplier_rejected():
    # Floats have already lost exactness; accepting one lets rounding decide soundness.
    atoms = [atom({"x": 1}, 1), atom({"x": -1}, 1)]
    res = verify_farkas(atoms, {0: 1.0, 1: 1.0})
    assert not res


# --------------------------------------------------------------------------- #
# property: a refutable system stays refutable under multiplier scaling
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("k", [1, 2, 3, 7, 100])
def test_scaling_a_valid_certificate_preserves_validity(k):
    atoms = [atom({"x": 1}, 1), atom({"x": -1}, 1)]
    assert verify_farkas(atoms, {0: k, 1: k})


def test_negate_roundtrip():
    a = atom({"x": 1, "y": -2}, 3, strict=False)
    n = negate(a)
    assert n.strict is True
    assert n.coeff == {"x": Fraction(-1), "y": Fraction(2)}
    assert n.const == Fraction(-3)
    assert negate(n) == a
