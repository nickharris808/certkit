"""Farkas certificate checking -- the load-bearing ~30 lines of this package.

A *Farkas certificate* witnesses that a conjunction of linear atoms is
unsatisfiable over the rationals. It is a vector of nonnegative multipliers, one
per atom, such that the multiplied atoms sum to a contradiction: every variable
cancels, and the surviving constant is impossible.

Why that is sound, in one paragraph. If every atom ``L_i <= 0`` holds and every
multiplier ``m_i >= 0``, then ``sum(m_i * L_i) <= 0`` necessarily. If the
multipliers are chosen so that all variable coefficients cancel, the left side
collapses to a constant ``c``. So ``c <= 0`` must hold. If instead ``c > 0``, no
assignment can satisfy the conjunction -- the system is infeasible. When any atom
used with a nonzero multiplier is *strict* (``< 0``), the combination is strict
too, so ``c >= 0`` already suffices for the contradiction.

Why rational infeasibility is enough for integer problems: the integers are a
subset of the rationals, so a system with no rational solution has no integer
solution either. The converse does not hold, which is why a failure to find a
Farkas certificate is *not* a proof of satisfiability -- this checker refuses,
it does not certify the negation.

Checking is O(number of nonzero multipliers x atom size) and uses only exact
rational arithmetic. Finding the multipliers is somebody else's problem: this
package deliberately contains no search, no solver, and no LP. That asymmetry is
the point of proof-carrying verification -- the producer may be arbitrarily
clever and arbitrarily untrusted, because the checker is small enough to audit.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from fractions import Fraction
from typing import Any

from .atoms import Atom

__all__ = ["verify_farkas", "FarkasResult"]


class FarkasResult:
    """Outcome of a certificate check, with a reason when it fails.

    Truthy when the certificate is valid, so ``if verify_farkas(...):`` reads
    naturally, while ``.reason`` explains a rejection.
    """

    __slots__ = ("ok", "reason")

    def __init__(self, ok: bool, reason: str = "") -> None:
        self.ok = ok
        self.reason = reason

    def __bool__(self) -> bool:
        return self.ok

    def __repr__(self) -> str:
        return f"FarkasResult(ok={self.ok!r}, reason={self.reason!r})"


def verify_farkas(
    atoms: Sequence[Atom],
    multipliers: Mapping[Any, Any],
) -> FarkasResult:
    """Check a Farkas certificate for the conjunction ``atoms``.

    ``multipliers`` maps an atom index to a nonnegative rational weight. Indices
    may arrive as strings (JSON object keys are always strings), so they are
    coerced; anything that is not a valid in-range index is a rejection rather
    than an exception. That matters: this function is fed attacker-controlled
    input, and a checker that raises on malformed input is a denial-of-service
    surface at best and a bypass at worst.

    Returns a :class:`FarkasResult` -- truthy exactly when the multipliers prove
    the conjunction infeasible.
    """
    if not multipliers:
        return FarkasResult(False, "empty multiplier vector")

    combined: dict[str, Fraction] = {}
    const = Fraction(0)
    any_strict = False
    used = 0

    for raw_index, raw_weight in multipliers.items():
        # --- coerce and validate the index -------------------------------
        try:
            index = int(raw_index)
        except (TypeError, ValueError):
            return FarkasResult(False, f"non-integer atom index {raw_index!r}")
        if index < 0 or index >= len(atoms):
            return FarkasResult(False, f"atom index {index} out of range")

        # --- coerce and validate the weight ------------------------------
        try:
            weight = _as_fraction(raw_weight)
        except (TypeError, ValueError, ZeroDivisionError):
            return FarkasResult(False, f"malformed multiplier {raw_weight!r}")
        if weight < 0:
            return FarkasResult(False, f"negative multiplier {weight} at index {index}")
        if weight == 0:
            continue  # a zero weight contributes nothing and is not "use"

        # --- accumulate ---------------------------------------------------
        a = atoms[index]
        for v, c in a.coeff.items():
            combined[v] = combined.get(v, Fraction(0)) + weight * c
        const += weight * a.const
        any_strict = any_strict or a.strict
        used += 1

    if used == 0:
        return FarkasResult(False, "all multipliers zero")

    residual = {v: c for v, c in combined.items() if c != 0}
    if residual:
        names = ", ".join(sorted(residual))
        return FarkasResult(False, f"variables did not cancel: {names}")

    # A strict atom makes the combination strict, so const >= 0 already
    # contradicts "< 0". Otherwise we need a genuinely positive constant.
    if any_strict:
        if const >= 0:
            return FarkasResult(True)
        return FarkasResult(False, f"strict combination needs const >= 0, got {const}")
    if const > 0:
        return FarkasResult(True)
    return FarkasResult(False, f"non-strict combination needs const > 0, got {const}")


def _as_fraction(value: Any) -> Fraction:
    """Coerce a JSON-ish weight to an exact Fraction.

    Accepts ``5``, ``"5"``, ``"3/4"``, ``[3, 4]``, and ``Fraction``. Rejects
    floats: a multiplier that arrived as a float has already lost exactness, and
    silently accepting it would let rounding decide soundness.
    """
    if isinstance(value, Fraction):
        return value
    if isinstance(value, bool):
        raise TypeError("bool is not a multiplier")
    if isinstance(value, int):
        return Fraction(value)
    if isinstance(value, (list, tuple)):
        if len(value) != 2:
            raise ValueError("pair form must be [numerator, denominator]")
        return Fraction(int(value[0]), int(value[1]))
    if isinstance(value, str):
        return Fraction(value)
    raise TypeError(f"unsupported multiplier type {type(value).__name__}")
