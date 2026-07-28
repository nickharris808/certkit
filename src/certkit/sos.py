"""Sum-of-squares certificate checking -- the Farkas move one theory up.

Farkas handles *linear* infeasibility. For a *nonlinear* obligation of the form
``target(x) >= 0``, the analogous certificate is a rational sum-of-squares
identity::

    scale * target  ==  sum_i q_i^2

with ``scale`` a positive integer and each ``q_i`` a polynomial. Soundness is
immediate: every square is nonnegative and ``scale > 0``, so ``target >= 0``.

As with Farkas, an untrusted producer (typically a semidefinite-programming
relaxation) *finds* the ``q_i``; this checker only re-multiplies them and
verifies the polynomial identity holds exactly over the rationals. A perturbed
certificate fails, because every monomial coefficient must cancel to zero -- there
is no tolerance to tune.

Scope, honestly: sum-of-squares is incomplete. A nonnegative polynomial need not
admit an SOS decomposition (Motzkin's polynomial is the standard witness), and
nonnegativity over the integers or over a non-compact domain is a different
question again. A refusal here means "no certificate was supplied or it did not
check", never "the target is negative".

Polynomials are dicts from exponent tuples to Fractions. The JSON form encodes a
monomial as a comma-joined exponent string over the certificate's declared
variable order: ``"2,0"`` is ``x^2``, ``"1,1"`` is ``x*y``, ``"0,0"`` is the
constant term.
"""

from __future__ import annotations

from collections.abc import Mapping
from fractions import Fraction
from typing import Any

__all__ = ["verify_sos", "SOS_SCHEMA", "parse_polynomial"]

SOS_SCHEMA = "certkit/sos/v1"

Monomial = tuple[int, ...]
Polynomial = dict[Monomial, Fraction]


def _parse_monomial(key: str) -> Monomial:
    return tuple(int(e) for e in key.split(","))


def parse_polynomial(d: Mapping[str, Any]) -> Polynomial:
    """Parse ``{"2,0": [3,1], ...}`` into ``{(2,0): Fraction(3,1), ...}``."""
    out: Polynomial = {}
    for k, v in d.items():
        n, dd = v
        c = Fraction(int(n), int(dd))
        if c != 0:
            out[_parse_monomial(k)] = c
    return out


def _poly_add(a: Polynomial, b: Polynomial, scale: Fraction = Fraction(1)) -> Polynomial:
    out = dict(a)
    for m, c in b.items():
        out[m] = out.get(m, Fraction(0)) + scale * c
    return {m: c for m, c in out.items() if c != 0}


def _poly_mul(a: Polynomial, b: Polynomial) -> Polynomial:
    out: Polynomial = {}
    for ma, ca in a.items():
        for mb, cb in b.items():
            # Exponent vectors add under multiplication. Pad to equal arity so a
            # certificate cannot smuggle a shape mismatch past us.
            width = max(len(ma), len(mb))
            ea = ma + (0,) * (width - len(ma))
            eb = mb + (0,) * (width - len(mb))
            m = tuple(x + y for x, y in zip(ea, eb))
            out[m] = out.get(m, Fraction(0)) + ca * cb
    return {m: c for m, c in out.items() if c != 0}


def verify_sos(cert: Mapping[str, Any]) -> bool:
    """Re-check a rational sum-of-squares certificate.

    Returns ``True`` only when the schema tag matches, ``scale`` is a positive
    integer, the square list is non-empty with no zero polynomial, and the
    identity ``scale*target == sum q_i^2`` holds exactly.
    """
    if not isinstance(cert, Mapping) or cert.get("schema") != SOS_SCHEMA:
        return False

    squares = cert.get("squares")
    if not isinstance(squares, list) or not squares:
        return False

    try:
        scale = int(cert["scale"])
        target = parse_polynomial(cert["target"])
        qs = [parse_polynomial(q) for q in squares]
    except Exception:
        # Malformed input is a rejection, never a traceback.
        return False

    if scale <= 0:
        return False
    if any(not q for q in qs):
        # An empty polynomial is the zero polynomial; allowing it would let a
        # certificate pad its square list without contributing anything.
        return False

    sos: Polynomial = {}
    for q in qs:
        sos = _poly_add(sos, _poly_mul(q, q))

    scaled_target = {m: scale * c for m, c in target.items()}
    residual = _poly_add(scaled_target, sos, scale=Fraction(-1))
    return len(residual) == 0
