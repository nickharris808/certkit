"""Turn a written-out inequality into a spec, so nobody hand-writes JSON atoms.

The canonical atom form is deliberate -- ``{"coeff": {"payload": [1, 1]}, ...}``
is unambiguous, exactly representable, and easy to check. It is also a miserable
thing to type, and requiring it before a newcomer can run anything is a barrier
with no payoff. This module parses the relation people actually write:

    19 + payload <= record_len
    0 <= payload
    2*offset + len < size

and emits the canonical form. The parser is deliberately small: linear integer
relations only, one comparison per line. Anything it does not understand is an
error naming the offending text, never a guess -- a spec silently parsed into
the wrong relation would be far worse than a rejected one, because everything
downstream would then prove the wrong thing.
"""

from __future__ import annotations

import re
from fractions import Fraction

from .atoms import Atom, atom
from .cert import make_spec

__all__ = ["parse_relation", "build_spec", "RelationSyntaxError"]


class RelationSyntaxError(ValueError):
    """A relation could not be parsed. Carries the offending text."""


_TOKEN = re.compile(
    r"""
    \s*(?:
        (?P<num>\d+)
      | (?P<name>[A-Za-z_][A-Za-z_0-9]*)
      | (?P<op><=|>=|<|>|==|=)
      | (?P<sym>[+\-*])
    )\s*
    """,
    re.VERBOSE,
)

_COMPARISONS = ("<=", ">=", "<", ">", "==", "=")


def _tokenise(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise RelationSyntaxError(
                f"cannot parse {text[pos : pos + 12]!r} in {text!r}. Supported syntax is a "
                f"linear relation such as '19 + payload <= record_len' or '2*n < size'."
            )
        kind = m.lastgroup or ""
        out.append((kind, m.group(kind)))
        pos = m.end()
    return out


def _parse_side(tokens: list[tuple[str, str]], source: str) -> tuple[dict[str, Fraction], Fraction]:
    """Parse one side of a comparison into (coefficients, constant)."""
    coeff: dict[str, Fraction] = {}
    const = Fraction(0)
    sign = 1
    pending: Fraction | None = None
    expect_term = True

    i = 0
    while i < len(tokens):
        kind, value = tokens[i]
        if kind == "sym" and value in "+-":
            if expect_term and pending is None and not coeff and const == 0 and i == 0:
                sign = -1 if value == "-" else 1
            else:
                sign = -1 if value == "-" else 1
            expect_term = True
            i += 1
            continue
        if kind == "num":
            n = Fraction(int(value))
            # "3*x" -- a coefficient; otherwise a bare constant.
            if i + 1 < len(tokens) and tokens[i + 1] == ("sym", "*"):
                pending = n
                i += 2
                continue
            const += sign * n
            sign = 1
            expect_term = False
            i += 1
            continue
        if kind == "name":
            c = (pending if pending is not None else Fraction(1)) * sign
            coeff[value] = coeff.get(value, Fraction(0)) + c
            pending = None
            sign = 1
            expect_term = False
            i += 1
            continue
        raise RelationSyntaxError(f"unexpected {value!r} in {source!r}")

    if pending is not None:
        raise RelationSyntaxError(f"trailing coefficient with no variable in {source!r}")
    return coeff, const


def parse_relation(text: str) -> Atom:
    """Parse ``lhs <op> rhs`` into a canonical atom (``... <= 0`` or ``... < 0``).

    ``a <= b`` becomes ``a - b <= 0``; ``a >= b`` becomes ``b - a <= 0``. An
    equality is rejected rather than silently split, because an atom is a single
    inequality and turning ``=`` into two of them would change the shape of the
    spec without saying so.
    """
    source = text.strip()
    if not source:
        raise RelationSyntaxError("empty relation")

    op = None
    for candidate in _COMPARISONS:
        idx = source.find(candidate)
        if idx != -1 and (op is None or idx < op[1] or len(candidate) > len(op[0])):
            if op is None or idx < op[1]:
                op = (candidate, idx)
    if op is None:
        raise RelationSyntaxError(
            f"no comparison operator in {source!r}. Write something like "
            f"'19 + payload <= record_len'."
        )

    name, idx = op
    # Prefer the two-character form when both match at the same position.
    for longer in ("<=", ">=", "=="):
        if source[idx : idx + 2] == longer:
            name = longer
            break

    if name in ("==", "="):
        raise RelationSyntaxError(
            f"equality is not a single atom: {source!r}. Write the two inequalities "
            f"you mean, e.g. 'a <= b' and 'b <= a'."
        )

    lhs_text, rhs_text = source[:idx], source[idx + len(name) :]
    lhs = _parse_side(_tokenise(lhs_text), source)
    rhs = _parse_side(_tokenise(rhs_text), source)

    if name in ("<=", "<"):
        left, right = lhs, rhs
    else:  # >= or >  -- flip so the atom is always "<= 0" shaped
        left, right = rhs, lhs

    coeff: dict[str, Fraction] = dict(left[0])
    for v, c in right[0].items():
        coeff[v] = coeff.get(v, Fraction(0)) - c
    const = left[1] - right[1]

    coeff = {v: c for v, c in coeff.items() if c != 0}
    if not coeff:
        raise RelationSyntaxError(
            f"{source!r} has no variables, so it is a constant claim, not a relation."
        )
    return atom(coeff, const, strict=name in ("<", ">"))


def build_spec(
    domain: list[str],
    guard: list[str],
    safety: list[str],
    name: str = "unnamed",
) -> dict:
    """Parse three lists of written relations into a fingerprinted spec."""

    def parse_all(items: list[str], label: str) -> list[Atom]:
        out = []
        for text in items:
            try:
                out.append(parse_relation(text))
            except RelationSyntaxError as exc:
                raise RelationSyntaxError(f"in --{label} {text!r}: {exc}") from exc
        return out

    if not safety:
        raise RelationSyntaxError(
            "a spec needs at least one --safety relation: the property you want proved."
        )
    return make_spec(
        parse_all(domain, "domain"),
        parse_all(guard, "guard"),
        parse_all(safety, "safety"),
        name=name,
    )
