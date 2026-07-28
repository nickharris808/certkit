"""Linear atoms over the rationals.

An atom is a linear relation in canonical form::

    sum(coeff[v] * v) + const  {< 0 if strict else <= 0}

Every relation a caller might write (``x <= y``, ``3*a + 2 < b``, ``x >= 0``) is
normalised into this single shape, so the checker has exactly one form to reason
about. That is deliberate: the trusted core stays small because it never has to
case-split on relational operators.

All arithmetic is exact (``fractions.Fraction``). There are no floats anywhere in
this package -- a floating-point rounding error in a proof checker is a soundness
bug, not a precision nuisance.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from fractions import Fraction
from typing import Any

__all__ = ["Atom", "atom", "negate", "atom_from_json", "atom_to_json"]


class Atom:
    """A linear relation ``sum(coeff*var) + const <= 0`` (or ``< 0`` when strict).

    Instances are immutable in practice; the checker never mutates an atom it was
    given. Construct with :func:`atom` for convenience.
    """

    __slots__ = ("coeff", "const", "strict")

    def __init__(
        self,
        coeff: Mapping[str, Fraction],
        const: Fraction = Fraction(0),
        strict: bool = False,
    ) -> None:
        # Drop zero coefficients so structurally equal atoms compare equal.
        self.coeff: dict[str, Fraction] = {
            v: Fraction(c) for v, c in coeff.items() if Fraction(c) != 0
        }
        self.const: Fraction = Fraction(const)
        self.strict: bool = bool(strict)

    def variables(self) -> Iterable[str]:
        return self.coeff.keys()

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Atom):
            return NotImplemented
        return (
            self.coeff == other.coeff and self.const == other.const and self.strict == other.strict
        )

    def __hash__(self) -> int:
        return hash((tuple(sorted(self.coeff.items())), self.const, self.strict))

    def __repr__(self) -> str:
        terms = " + ".join(f"{c}*{v}" for v, c in sorted(self.coeff.items()))
        rel = "<" if self.strict else "<="
        body = terms if terms else "0"
        if self.const:
            body = f"{body} + {self.const}"
        return f"Atom({body} {rel} 0)"


def atom(coeff: Mapping[str, Any], const: Any = 0, strict: bool = False) -> Atom:
    """Build an :class:`Atom`, coercing ints/strings/fractions to ``Fraction``."""
    return Atom({v: Fraction(c) for v, c in coeff.items()}, Fraction(const), strict)


def negate(a: Atom) -> Atom:
    """Logical negation of an atom.

    ``not (L <= 0)`` is ``-L < 0``; ``not (L < 0)`` is ``-L <= 0``. Negation flips
    every coefficient, the constant, and the strictness flag. This is the only
    place strictness inverts, and it is what lets a refutation be expressed as an
    infeasible conjunction.
    """
    return Atom(
        {v: -c for v, c in a.coeff.items()},
        -a.const,
        not a.strict,
    )


def atom_from_json(d: Mapping[str, Any]) -> Atom:
    """Parse an atom from the on-disk JSON form.

    Coefficients and the constant are ``[numerator, denominator]`` pairs so a
    certificate never depends on decimal parsing.
    """
    coeff = {v: Fraction(int(n), int(dd)) for v, (n, dd) in d["coeff"].items()}
    n, dd = d["const"]
    return Atom(coeff, Fraction(int(n), int(dd)), bool(d["strict"]))


def atom_to_json(a: Atom) -> dict[str, Any]:
    """Serialise an atom to the on-disk JSON form."""
    return {
        "coeff": {v: [c.numerator, c.denominator] for v, c in sorted(a.coeff.items())},
        "const": [a.const.numerator, a.const.denominator],
        "strict": a.strict,
    }
