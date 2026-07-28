"""SMT-LIB 2 bridge: emit an obligation a solver can check, and read one back.

SMT-LIB is the lingua franca of this field. Anything that already runs z3, cvc5
or CBMC speaks it, and until certkit did too, "bring your own producer" was an
instruction with no path attached. This module is that path:

    certkit export --spec s.json --smtlib -o obligation.smt2   # -> z3 obligation.smt2
    certkit import --smtlib f.smt2 -o s.json                   # <- back to a spec

**Export** is total: every certkit spec has an SMT-LIB rendering, because the
certkit fragment is a strict subset of QF_LIA. The emitted script asserts the
obligation `domain AND guard AND NOT(safety[i])` and asks `check-sat`. A solver
answering `unsat` agrees with an `ACCEPTED` certificate; `sat` means the guard
really does admit a forbidden state, and the model is a counterexample.

**Import is partial, and loudly so.** SMT-LIB is a large language and certkit
handles quantifier-free linear integer arithmetic and nothing else. Rather than
silently dropping what it does not understand -- which would produce a spec that
proves something *weaker* than the file said, the worst possible failure here --
the reader raises :class:`SmtLibUnsupported` naming the construct it refused.

A partial importer that guesses is worse than no importer, because everything
downstream would then be proving the wrong theorem, correctly.
"""

from __future__ import annotations

import re
from fractions import Fraction
from typing import Any

from .atoms import Atom, atom, atom_to_json
from .cert import SPEC_SCHEMA, fingerprint

__all__ = [
    "SmtLibError",
    "SmtLibUnsupported",
    "export_spec",
    "export_obligation",
    "import_spec",
    "parse_sexpr",
]


class SmtLibError(ValueError):
    """The SMT-LIB text could not be read."""


class SmtLibUnsupported(SmtLibError):
    """A construct outside certkit's fragment. Names what it refused."""


# --------------------------------------------------------------------------- #
# export
# --------------------------------------------------------------------------- #


def _term(a: Atom, *, negated: bool = False) -> str:
    """Render one atom as an SMT-LIB assertion body.

    An atom is ``sum(c*v) + k <= 0`` (or ``< 0``). Coefficients are exact
    rationals; when any denominator is not 1 we scale the whole atom by the LCM
    of the denominators, which preserves the relation exactly because the scale
    is positive. That keeps the emitted script in integer arithmetic, so a
    solver can use QF_LIA rather than QF_LRA.
    """
    denominators = [c.denominator for c in a.coeff.values()] + [a.const.denominator]
    scale = 1
    for d in denominators:
        scale = scale * d // _gcd(scale, d)

    parts = []
    for v in sorted(a.coeff):
        c = a.coeff[v] * scale
        assert c.denominator == 1
        n = int(c)
        if n == 0:
            continue
        parts.append(v if n == 1 else f"(* {_numeral(n)} {v})")
    const = a.const * scale
    assert const.denominator == 1
    k = int(const)

    if not parts:
        lhs = _numeral(k)
    elif k:
        lhs = f"(+ {' '.join(parts)} {_numeral(k)})"
    elif len(parts) == 1:
        lhs = parts[0]
    else:
        lhs = f"(+ {' '.join(parts)})"

    op = "<" if a.strict else "<="
    body = f"({op} {lhs} 0)"
    return f"(not {body})" if negated else body


def _numeral(n: int) -> str:
    """Render an integer as an SMT-LIB 2 term.

    ``-1`` is not a numeral in SMT-LIB 2 -- the grammar's numerals are
    non-negative, and a leading minus makes it a *symbol*. z3 accepts it as an
    extension; a standards-strict cvc5 reports `Symbol '-1' not declared as a
    variable` and refuses the whole script. The portable spelling is ``(- 1)``.
    """
    return str(n) if n >= 0 else f"(- {-n})"


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a) or 1


def _variables(atoms: list[Atom]) -> list[str]:
    seen: set[str] = set()
    for a in atoms:
        seen.update(v for v, c in a.coeff.items() if c != 0)
    return sorted(seen)


def export_obligation(
    domain: list[Atom],
    guard: list[Atom],
    safety: list[Atom],
    index: int,
    *,
    name: str = "obligation",
) -> str:
    """Emit `domain AND guard AND NOT(safety[index])` as an SMT-LIB 2 script."""
    if not safety:
        raise SmtLibError("a spec needs at least one safety conjunct")
    if not 0 <= index < len(safety):
        raise SmtLibError(f"safety_index {index} out of range (0..{len(safety) - 1})")

    all_atoms = list(domain) + list(guard) + [safety[index]]
    lines = [
        f"; certkit obligation {index} of {len(safety)} -- {name}",
        ";",
        "; unsat  => the guard implies this safety conjunct over the declared domain.",
        "; sat    => it does not, and the model is a counterexample.",
        ";",
        "; Integers, not machine words: this says nothing about wraparound.",
        "(set-logic QF_LIA)",
        "",
    ]
    for v in _variables(all_atoms):
        lines.append(f"(declare-const {v} Int)")
    lines.append("")

    for label, group in (("domain", domain), ("guard", guard)):
        if group:
            lines.append(f"; {label}")
            lines += [f"(assert {_term(a)})" for a in group]
            lines.append("")

    lines.append(f"; negated safety conjunct {index}")
    lines.append(f"(assert {_term(safety[index], negated=True)})")
    # `(get-model)` is left commented out on purpose. It is an error after
    # `unsat` -- which is the *success* case here -- and z3 then exits non-zero
    # with `model is not available`, so the proved case would look like a broken
    # run to anyone piping this into CI. Uncomment it when you get `sat` and want
    # the counterexample.
    lines += [
        "",
        "(check-sat)",
        "; (get-model)   ; uncomment after a `sat` result to see the counterexample",
        "",
    ]
    return "\n".join(lines)


def export_spec(spec: dict[str, Any]) -> list[str]:
    """One SMT-LIB script per safety conjunct, in spec order."""
    from .cert import _parse_spec_atoms

    prefix, safety = _parse_spec_atoms(spec)
    n_domain = len(spec.get("domain", []) or [])
    domain, guard = prefix[:n_domain], prefix[n_domain:]
    name = spec.get("name", "unnamed")
    return [export_obligation(domain, guard, safety, i, name=name) for i in range(len(safety))]


# --------------------------------------------------------------------------- #
# import -- restricted, and explicit about it
# --------------------------------------------------------------------------- #

_TOKEN = re.compile(r"\(|\)|[^\s()]+")


def parse_sexpr(text: str) -> list[Any]:
    """Tokenise SMT-LIB into nested lists. Comments and strings are stripped."""
    text = re.sub(r";[^\n]*", "", text)
    stack: list[list[Any]] = [[]]
    for tok in _TOKEN.findall(text):
        if tok == "(":
            stack.append([])
        elif tok == ")":
            if len(stack) == 1:
                raise SmtLibError("unbalanced ')' in SMT-LIB input")
            done = stack.pop()
            stack[-1].append(done)
        else:
            stack[-1].append(tok)
    if len(stack) != 1:
        raise SmtLibError("unbalanced '(' in SMT-LIB input")
    return stack[0]


_REL_FLIP = {"<=": ">=", "<": ">", ">=": "<=", ">": "<", "=": "="}


def _linear(node: Any, sign: Fraction = Fraction(1)) -> tuple[dict[str, Fraction], Fraction]:
    """Evaluate a term into (coefficients, constant). Refuses anything nonlinear."""
    if isinstance(node, str):
        try:
            return {}, sign * Fraction(node)
        except ValueError:
            pass
        if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", node):
            raise SmtLibUnsupported(f"cannot read the term {node!r} as a variable or number")
        return {node: sign}, Fraction(0)

    if not node:
        raise SmtLibError("empty term")
    head, *rest = node

    if head == "+":
        coeff: dict[str, Fraction] = {}
        const = Fraction(0)
        for r in rest:
            c, k = _linear(r, sign)
            for v, x in c.items():
                coeff[v] = coeff.get(v, Fraction(0)) + x
            const += k
        return coeff, const

    if head == "-":
        if len(rest) == 1:
            return _linear(rest[0], -sign)
        coeff, const = _linear(rest[0], sign)
        for r in rest[1:]:
            c, k = _linear(r, -sign)
            for v, x in c.items():
                coeff[v] = coeff.get(v, Fraction(0)) + x
            const += k
        return coeff, const

    if head == "*":
        # Exactly one non-constant factor, or it is not linear. Each factor is
        # evaluated rather than pattern-matched on being a bare numeral, because
        # a constant can arrive as a term: `(- 1)` is how SMT-LIB 2 spells -1,
        # and treating it as the variable part made `(* (- 1) x)` look nonlinear.
        factor = sign
        var_part: Any = None
        for r in rest:
            coeff_r, const_r = _linear(r)
            if not coeff_r:
                factor *= const_r
                continue
            if var_part is not None:
                raise SmtLibUnsupported(
                    "nonlinear multiplication: certkit handles linear arithmetic only"
                )
            var_part = r
        if var_part is None:
            return {}, factor
        return _linear(var_part, factor)

    raise SmtLibUnsupported(f"unsupported operator {head!r}; certkit handles + - * only")


def _atom_from_assert(node: Any) -> Atom:
    """Turn one `(assert ...)` body into a canonical atom."""
    negated = False
    if isinstance(node, list) and node and node[0] == "not":
        if len(node) != 2:
            raise SmtLibError("(not ...) takes exactly one argument")
        negated, node = True, node[1]

    if not isinstance(node, list) or len(node) != 3:
        raise SmtLibUnsupported(
            "each assertion must be a single binary comparison such as (<= (+ x 1) y)"
        )
    rel, lhs, rhs = node
    if rel == "=":
        raise SmtLibUnsupported(
            "an equality is two atoms; assert the two inequalities you mean instead"
        )
    if rel not in _REL_FLIP:
        raise SmtLibUnsupported(f"unsupported relation {rel!r}; use <=, <, >= or >")

    lc, lk = _linear(lhs)
    rc, rk = _linear(rhs)

    if rel in (">=", ">"):
        lc, rc, lk, rk = rc, lc, rk, lk
        rel = "<=" if rel == ">=" else "<"

    coeff = dict(lc)
    for v, x in rc.items():
        coeff[v] = coeff.get(v, Fraction(0)) - x
    const = lk - rk
    strict = rel == "<"

    if negated:
        coeff = {v: -x for v, x in coeff.items()}
        const, strict = -const, not strict

    coeff = {v: x for v, x in coeff.items() if x != 0}
    if not coeff:
        raise SmtLibUnsupported(
            "an assertion with no variables is a constant claim, not a relation"
        )
    return atom(coeff, const, strict=strict)


_KNOWN_COMMANDS = {
    "set-logic",
    "set-info",
    "set-option",
    "declare-const",
    "declare-fun",
    "assert",
    "check-sat",
    "get-model",
    "get-value",
    "exit",
    "push",
    "pop",
    "echo",
}


def import_spec(text: str, *, name: str = "imported") -> dict[str, Any]:
    """Read an SMT-LIB script into a certkit spec.

    Every assertion becomes a **safety** conjunct, because the file states what
    must hold and carries no notion of which relations are assumptions. Move
    atoms into ``domain`` and ``guard`` yourself -- that is a modelling decision,
    and guessing it would silently change what gets proved.

    Raises :class:`SmtLibUnsupported`, naming the construct, for anything outside
    quantifier-free linear integer arithmetic.
    """
    forms = parse_sexpr(text)
    asserts: list[Atom] = []
    declared: set[str] = set()

    for form in forms:
        if not isinstance(form, list) or not form:
            raise SmtLibError(f"expected a command, got {form!r}")
        cmd = form[0]
        if cmd == "assert":
            if len(form) != 2:
                raise SmtLibError("(assert ...) takes exactly one argument")
            asserts.append(_atom_from_assert(form[1]))
        elif cmd in ("declare-const", "declare-fun"):
            if cmd == "declare-fun" and len(form) >= 3 and form[2]:
                raise SmtLibUnsupported(
                    f"uninterpreted function {form[1]!r}: certkit has no function symbols"
                )
            sort = form[-1]
            if sort not in ("Int",):
                raise SmtLibUnsupported(
                    f"sort {sort!r} for {form[1]!r}: certkit handles Int only "
                    "(no Real, Bool, or BitVec)"
                )
            declared.add(form[1])
        elif cmd in ("forall", "exists"):
            raise SmtLibUnsupported("quantifiers: certkit's fragment is quantifier-free")
        elif cmd not in _KNOWN_COMMANDS:
            raise SmtLibUnsupported(f"unsupported command {cmd!r}")

    if not asserts:
        raise SmtLibError("no assertions found, so there is nothing to prove")

    undeclared = sorted({v for a in asserts for v in a.coeff} - declared)
    if undeclared:
        raise SmtLibError(
            f"assertion mentions undeclared variable(s): {', '.join(undeclared)}. "
            "Add (declare-const <name> Int)."
        )

    body: dict[str, Any] = {
        "schema": SPEC_SCHEMA,
        "name": name,
        "domain": [],
        "guard": [],
        "safety": [atom_to_json(a) for a in asserts],
    }
    body["fingerprint"] = fingerprint(dict(body.items()))
    return body
