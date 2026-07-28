"""Render a refutation as arithmetic a human can follow.

A Farkas certificate is a vector of numbers. That is wonderful for a machine and
close to useless for a person: ``{"2": 1, "3": 1}`` does not look like a proof,
it looks like a hash. But the underlying argument is genuinely simple, and a
reader who is asked to trust the format deserves to see it worked out:

    take each atom, multiply it by its weight, add them up, observe that every
    variable cancels, observe that the surviving constant is impossible.

That is the whole proof, and this module prints exactly those steps with the
real numbers in them. It re-derives everything from the spec and the multipliers
rather than trusting any narrative the certificate carries, so the explanation
cannot disagree with the verdict.

Nothing here is part of the trusted path: :func:`certkit.verify_farkas` decides,
this only describes. If the two ever disagree, the checker is right.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from fractions import Fraction
from typing import Any

from .atoms import Atom
from .cert import reconstruct_obligation
from .farkas import _as_fraction, verify_farkas

__all__ = ["format_atom", "explain_obligation", "explain_certificate"]


def _num(x: Fraction) -> str:
    """A rational, printed the way a person writes it."""
    return str(x.numerator) if x.denominator == 1 else f"{x.numerator}/{x.denominator}"


def format_atom(a: Atom) -> str:
    """Render an atom as the inequality it means, e.g. ``payload - record_len + 19 <= 0``."""
    parts: list[str] = []
    for v in sorted(a.coeff):
        c = a.coeff[v]
        if c == 0:
            continue
        sign = "-" if c < 0 else "+"
        mag = abs(c)
        term = v if mag == 1 else f"{_num(mag)}*{v}"
        parts.append(f"{sign} {term}" if parts else (f"-{term}" if c < 0 else term))
    if a.const or not parts:
        sign = "-" if a.const < 0 else "+"
        parts.append(f"{sign} {_num(abs(a.const))}" if parts else _num(a.const))
    return f"{' '.join(parts)} {'<' if a.strict else '<='} 0"


def explain_obligation(
    atoms: Sequence[Atom],
    multipliers: Mapping[Any, Any],
    *,
    index: int = 0,
) -> str:
    """Show the weighted sum that refutes ``atoms``, term by term."""
    lines: list[str] = []
    result = verify_farkas(atoms, multipliers)

    lines.append(f"Obligation {index}: is this system satisfiable?")
    lines.append("")
    for i, a in enumerate(atoms):
        lines.append(f"    [{i}]  {format_atom(a)}")
    lines.append("")

    if not result:
        lines.append(f"  The supplied multipliers do NOT refute it: {result.reason}")
        lines.append("")
        lines.append("  That means 'not proven'. It is not a proof that the system IS")
        lines.append("  satisfiable -- certkit refuses, it never certifies the negation.")
        return "\n".join(lines)

    # Re-derive the combination so the arithmetic shown is the arithmetic checked.
    used: list[tuple[int, Fraction, Atom]] = []
    for raw_index, raw_weight in multipliers.items():
        weight = _as_fraction(raw_weight)
        if weight == 0:
            continue
        used.append((int(raw_index), weight, atoms[int(raw_index)]))
    used.sort()

    lines.append("  Multiply each atom by its nonnegative weight and add:")
    lines.append("")
    combined: dict[str, Fraction] = {}
    const = Fraction(0)
    any_strict = False
    for i, weight, a in used:
        lines.append(f"    {_num(weight)} * [{i}]    ({format_atom(a)})")
        for v, c in a.coeff.items():
            combined[v] = combined.get(v, Fraction(0)) + weight * c
        const += weight * a.const
        any_strict = any_strict or a.strict
    lines.append("")

    surviving = {v: c for v, c in combined.items() if c != 0}
    cancelled = sorted(v for v, c in combined.items() if c == 0)
    if cancelled:
        lines.append(f"  Every variable cancels: {', '.join(cancelled)} all sum to 0.")
    else:
        lines.append("  No variables appear in the sum.")
    if surviving:  # unreachable when verify_farkas said ok; kept honest anyway
        lines.append(f"  Left over: {surviving!r}")
    lines.append("")

    relation = "<" if any_strict else "<="
    lines.append(f"  What remains is:  {_num(const)} {relation} 0")
    lines.append("")
    if any_strict:
        lines.append(f"  At least one atom was strict, so the sum is strict: {_num(const)} < 0.")
    lines.append(
        "  That is false, so the system has no solution. Within the declared\n"
        "  domain, the guard implies the safety property."
    )
    return "\n".join(lines)


def explain_certificate(spec: Mapping[str, Any], cert: Mapping[str, Any]) -> str:
    """Explain every obligation of a spec/certificate pair."""
    safety = spec.get("safety") or []
    obligations = cert.get("obligations") or []
    body = {k: v for k, v in spec.items() if k != "fingerprint"}

    out: list[str] = []
    name = spec.get("name", "<unnamed>")
    out.append(f"certkit explain -- {name}")
    out.append("=" * (18 + len(str(name))))
    out.append("")
    out.append(
        "The claim: within the declared domain, the guard implies every safety\n"
        "conjunct. Each conjunct becomes one obligation, refuted separately."
    )
    out.append("")

    if not safety:
        out.append("This spec has no safety conjuncts, so there is nothing to prove.")
        return "\n".join(out)

    for i in range(len(safety)):
        sub = dict(body)
        sub["safety_index"] = i
        try:
            atoms = reconstruct_obligation(sub)
        except (ValueError, TypeError, KeyError, AttributeError, ArithmeticError) as exc:
            out.append(f"Obligation {i}: cannot be rebuilt from the spec: {exc}")
            out.append("")
            continue

        entry = obligations[i] if i < len(obligations) else {}
        multipliers = entry.get("multipliers") if isinstance(entry, Mapping) else None
        if not isinstance(multipliers, Mapping):
            out.append(f"Obligation {i}: the certificate supplies no multipliers for it.")
            out.append("")
            continue

        try:
            out.append(explain_obligation(atoms, multipliers, index=i))
        except (TypeError, ValueError, ArithmeticError) as exc:
            out.append(f"Obligation {i}: multipliers are malformed: {exc}")
        out.append("")

    out.append("-" * 60)
    out.append(
        "The atoms above were rebuilt from the spec. Any atoms the certificate\n"
        "carried were ignored, which is why a certificate proving some easier\n"
        "unrelated system cannot pass here."
    )
    return "\n".join(out)
