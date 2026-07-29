"""SMT-LIB bridge (stress-test item S2).

Two properties, and the second is the one that matters.

**Round-trip.** Exporting an obligation and reading it back must yield the same
atoms. If the writer and reader disagree, a spec that went out through one and
came back through the other would quietly become a different theorem.

**Differential against a real solver.** certkit and z3/cvc5 are entirely
independent implementations of the same question. If certkit accepts a
certificate, the exported obligation must be `unsat`; if the guard genuinely
admits a forbidden state, it must be `sat`. A disagreement is a soundness bug in
whichever is wrong, and this is how it would be caught.

The solver tests skip when no solver is installed, rather than silently passing.
Set ``CERTKIT_REQUIRE_SOLVERS=1`` -- as CI does -- and a missing solver becomes a
failure instead of a skip, so the documented cross-check cannot quietly stop
running.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

from certkit import atom, check_certificate, make_spec
from certkit.atoms import atom_from_json
from certkit.cert import reconstruct_obligation
from certkit.cli import example_path
from certkit.cli import main as cli_main
from certkit.smtlib import (
    SmtLibError,
    SmtLibUnsupported,
    export_obligation,
    export_spec,
    import_spec,
    parse_sexpr,
)

#: The solvers this suite knows how to drive. Fixed, not discovered: parametrising
#: over what happens to be installed makes the *collected test count* depend on
#: the machine, which broke the README-count check between a laptop with two
#: solvers and a CI runner with none. Availability is now a skip at run time,
#: where it belongs, and collection is identical everywhere.
KNOWN_SOLVERS = ("z3", "cvc5")
SOLVERS = [s for s in KNOWN_SOLVERS if shutil.which(s)]
REQUIRED = os.environ.get("CERTKIT_REQUIRE_SOLVERS") == "1"


def test_solvers_are_present_when_required():
    """The README says the bridge is cross-checked against a real solver in CI.

    A skip is invisible in a green run, so a CI image that lost its solver would
    turn that sentence into a claim nothing tests. This makes it loud.
    """
    if not REQUIRED:
        pytest.skip("CERTKIT_REQUIRE_SOLVERS is not set; solver tests may skip")
    assert SOLVERS, "CERTKIT_REQUIRE_SOLVERS=1 but no solver is on PATH"


DOMAIN = [atom({"payload": -1}), atom({"payload": 1}, -65535)]
GUARD = [atom({"payload": 1, "record_len": -1}, 19)]
SAFETY = [atom({"payload": 1, "record_len": -1}, 3)]
SPEC = make_spec(DOMAIN, GUARD, SAFETY, name="heartbleed")


def _same(a, b) -> bool:
    return a.coeff == b.coeff and a.const == b.const and a.strict == b.strict


def _require(solver: str) -> None:
    """Skip when this solver is absent -- unless CI has demanded one be present.

    A skip is invisible in a green run, which is why CERTKIT_REQUIRE_SOLVERS
    exists; this keeps that guarantee while making collection deterministic.
    """
    if solver not in SOLVERS:
        if REQUIRED and not SOLVERS:
            pytest.fail("CERTKIT_REQUIRE_SOLVERS=1 but no solver is on PATH")
        pytest.skip(f"{solver} is not installed")


def _run_solver(solver: str, script: str, tmp_path) -> str:
    path = tmp_path / f"{solver}.smt2"
    path.write_text(script, encoding="utf-8")
    out = subprocess.run([solver, str(path)], capture_output=True, text=True, timeout=120)
    return out.stdout.strip().splitlines()[0] if out.stdout.strip() else ""


# --------------------------------------------------------------------------- #
# export
# --------------------------------------------------------------------------- #


def test_export_emits_one_script_per_conjunct():
    spec = make_spec(DOMAIN, GUARD, [SAFETY[0], atom({"payload": -1}, 0)], name="two")
    assert len(export_spec(spec)) == 2


def test_export_declares_every_variable_it_uses():
    script = export_spec(SPEC)[0]
    assert "(declare-const payload Int)" in script
    assert "(declare-const record_len Int)" in script
    assert "(set-logic QF_LIA)" in script


def test_export_negates_the_safety_conjunct():
    """The obligation is domain AND guard AND NOT(safety) -- unsat means proved."""
    script = export_spec(SPEC)[0]
    assert "(assert (not " in script
    assert script.count("(assert ") == 4  # 2 domain + 1 guard + 1 negated safety


def test_export_says_what_unsat_means():
    """A bare script invites misreading; the comment is part of the output."""
    script = export_spec(SPEC)[0]
    assert "unsat" in script and "implies" in script
    assert "wraparound" in script  # integers, not machine words


def test_export_scales_rational_coefficients_to_integers():
    """Halves must not leak into a QF_LIA script."""
    from fractions import Fraction

    a = [atom({"x": Fraction(1, 2)}, Fraction(-3, 4))]
    script = export_obligation([], [], a, 0)
    assert "/" not in script.split("(set-logic")[1]
    assert "QF_LIA" in script


def test_export_rejects_an_out_of_range_index():
    with pytest.raises(SmtLibError):
        export_obligation(DOMAIN, GUARD, SAFETY, 5)
    with pytest.raises(SmtLibError):
        export_obligation(DOMAIN, GUARD, [], 0)


# --------------------------------------------------------------------------- #
# round-trip: writer and reader must agree
# --------------------------------------------------------------------------- #


def test_export_import_round_trip_preserves_the_obligation():
    """Read back what we wrote, and get the same atom list."""
    body = {k: v for k, v in SPEC.items() if k != "fingerprint"}
    body["safety_index"] = 0
    original = reconstruct_obligation(body)

    reimported = import_spec(export_spec(SPEC)[0])
    got = [atom_from_json(a) for a in reimported["safety"]]

    assert len(got) == len(original)
    for a, b in zip(got, original):
        assert _same(a, b), (a.coeff, b.coeff)


@pytest.mark.parametrize("g,s", [(19, 3), (1, 3), (0, 0), (5, 5), (100, 7)])
def test_round_trip_over_many_shapes(g, s):
    spec = make_spec(
        DOMAIN,
        [atom({"payload": 1, "record_len": -1}, g)],
        [atom({"payload": 1, "record_len": -1}, s)],
        name="rt",
    )
    body = {k: v for k, v in spec.items() if k != "fingerprint"}
    body["safety_index"] = 0
    original = reconstruct_obligation(body)
    got = [atom_from_json(a) for a in import_spec(export_spec(spec)[0])["safety"]]
    assert all(_same(a, b) for a, b in zip(got, original))


def test_parse_sexpr_handles_comments_and_nesting():
    forms = parse_sexpr("; a comment\n(assert (<= (+ x 1) y)) ; trailing\n")
    assert forms == [["assert", ["<=", ["+", "x", "1"], "y"]]]


# --------------------------------------------------------------------------- #
# the importer refuses everything outside the fragment, by name
# --------------------------------------------------------------------------- #


# Each entry: the input, and a word the refusal must contain. A refusal that
# does not name what it refused sends the reader hunting through their file.
UNSUPPORTED = {
    "nonlinear": ("(declare-const x Int)(declare-const y Int)(assert (<= (* x y) 3))", "nonlinear"),
    "equality": ("(declare-const x Int)(assert (= x 3))", "equality"),
    "real sort": ("(declare-const x Real)(assert (<= x 3))", "Real"),
    "bitvector": ("(declare-const x (_ BitVec 32))(assert (<= x 3))", "BitVec"),
    "bool sort": ("(declare-const x Bool)(assert (<= x 3))", "Bool"),
    "function": ("(declare-fun f (Int) Int)(assert (<= 1 2))", "'f'"),
    "unknown command": ("(declare-const x Int)(simplify x)(assert (<= x 3))", "simplify"),
    "constant claim": ("(declare-const x Int)(assert (<= 3 5))", "no variables"),
    "unsupported op": ("(declare-const x Int)(assert (<= (div x 2) 3))", "div"),
}


@pytest.mark.parametrize("label", sorted(UNSUPPORTED))
def test_unsupported_constructs_are_refused_by_name(label):
    text, expected = UNSUPPORTED[label]
    with pytest.raises(SmtLibUnsupported) as exc:
        import_spec(text)
    assert expected in str(exc.value), f"{label}: refusal did not name it -- {exc.value}"


MALFORMED = [
    "(declare-const x Int",  # unbalanced
    "(assert (<= x 3))",  # undeclared variable
    "(declare-const x Int)(check-sat)",  # nothing asserted
    "(declare-const x Int)(assert)",  # assert with no body
    "(declare-const x Int)(assert (<= x))",  # unary comparison
    "not-a-command",
    ")",
]


@pytest.mark.parametrize("text", MALFORMED)
def test_malformed_input_raises_smtliberror_not_something_else(text):
    with pytest.raises(SmtLibError):
        import_spec(text)


def test_import_does_not_guess_which_atoms_are_assumptions():
    """An SMT-LIB file does not say which relations are domain vs guard vs safety.

    Guessing would silently change what gets proved, so everything lands in
    safety and the caller is told to sort it out.
    """
    spec = import_spec("(declare-const x Int)(assert (<= x 3))(assert (<= 0 x))")
    assert spec["domain"] == []
    assert spec["guard"] == []
    assert len(spec["safety"]) == 2


def test_imported_spec_is_fingerprinted_and_valid():
    spec = import_spec("(declare-const x Int)(assert (<= x 3))")
    assert len(spec["fingerprint"]) == 64
    jsonschema = pytest.importorskip("jsonschema")
    from certkit.schemas import load_schema

    jsonschema.validate(spec, load_schema("certkit/spec/v1"))


# --------------------------------------------------------------------------- #
# differential against a real solver -- the point of the exercise
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("solver", KNOWN_SOLVERS)
def test_solver_says_unsat_when_certkit_accepts(solver, tmp_path):
    _require(solver)
    """certkit ACCEPTED means the obligation is infeasible. A solver must agree."""
    cert = json.loads(example_path("heartbleed.cert.json").read_text(encoding="utf-8"))
    spec = json.loads(example_path("heartbleed.spec.json").read_text(encoding="utf-8"))
    assert check_certificate(spec, cert).ok is True
    assert _run_solver(solver, export_spec(spec)[0], tmp_path) == "unsat"


@pytest.mark.parametrize("solver", KNOWN_SOLVERS)
def test_solver_says_sat_when_the_guard_is_genuinely_unsound(solver, tmp_path):
    _require(solver)
    """The converse direction: a real gap must show up as a model."""
    weak = make_spec(DOMAIN, [atom({"payload": 1, "record_len": -1}, 1)], SAFETY, name="weak")
    assert _run_solver(solver, export_spec(weak)[0], tmp_path) == "sat"


@pytest.mark.parametrize("solver", KNOWN_SOLVERS)
def test_differential_certkit_versus_solver_across_many_guards(solver, tmp_path):
    _require(solver)
    """Sweep guard/safety pairs; certkit's verdict and the solver must never differ.

    certkit accepts exactly when guard_overhead >= safety_overhead, because that
    is when the two atoms cancel to a contradiction. The solver decides the same
    question from the SMT-LIB text alone.
    """
    for gk in range(0, 6):
        for sk in range(0, 6):
            spec = make_spec(
                DOMAIN,
                [atom({"payload": 1, "record_len": -1}, gk)],
                [atom({"payload": 1, "record_len": -1}, sk)],
                name=f"g{gk}s{sk}",
            )
            cert = {
                "schema": "certkit/farkas/v1",
                "spec_fingerprint": spec["fingerprint"],
                "obligations": [{"multipliers": {"2": 1, "3": 1}}],
            }
            certkit_proves = check_certificate(spec, cert).ok
            solver_says = _run_solver(solver, export_spec(spec)[0], tmp_path)

            assert solver_says in ("sat", "unsat"), (gk, sk, solver_says)
            if certkit_proves:
                # A proof is never wrong: if certkit accepted, it must be unsat.
                assert solver_says == "unsat", (gk, sk)
            if solver_says == "sat":
                # And a real counterexample must never have been accepted.
                assert not certkit_proves, (gk, sk)


@pytest.mark.skipif(len(SOLVERS) < 2, reason="need two solvers to cross-check")  # noqa: PT031
def test_two_independent_solvers_agree(tmp_path):
    for gk, sk in ((19, 3), (1, 3), (3, 3), (0, 5)):
        spec = make_spec(
            DOMAIN,
            [atom({"payload": 1, "record_len": -1}, gk)],
            [atom({"payload": 1, "record_len": -1}, sk)],
            name="x",
        )
        script = export_spec(spec)[0]
        answers = {s: _run_solver(s, script, tmp_path) for s in SOLVERS}
        assert len(set(answers.values())) == 1, (gk, sk, answers)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_export_writes_a_script(tmp_path, capsys):
    spec_path = tmp_path / "s.json"
    spec_path.write_text(json.dumps(SPEC), encoding="utf-8")
    out = tmp_path / "o.smt2"
    assert cli_main(["export", "--spec", str(spec_path), "--smtlib", "-o", str(out)]) == 0
    assert "(check-sat)" in out.read_text(encoding="utf-8")
    assert "unsat means" in capsys.readouterr().out


def test_cli_export_to_stdout(capsys):
    assert cli_main(["export", "--spec", str(example_path("heartbleed.spec.json"))]) == 0
    assert "(set-logic QF_LIA)" in capsys.readouterr().out


def test_cli_import_round_trips_through_files(tmp_path, capsys):
    smt = tmp_path / "in.smt2"
    smt.write_text(
        "(declare-const x Int)\n(assert (<= (+ x 1) 10))\n(check-sat)\n", encoding="utf-8"
    )
    out = tmp_path / "spec.json"
    assert cli_main(["import", "--smtlib", str(smt), "-o", str(out)]) == 0
    spec = json.loads(out.read_text(encoding="utf-8"))
    assert spec["schema"] == "certkit/spec/v1"
    assert len(spec["safety"]) == 1
    # It must tell the user that the domain/guard split is theirs to make.
    assert "does not say which is which" in capsys.readouterr().out


def test_cli_import_reports_an_unsupported_construct(tmp_path, capsys):
    smt = tmp_path / "bad.smt2"
    smt.write_text("(declare-const x Real)\n(assert (<= x 3))\n", encoding="utf-8")
    assert cli_main(["import", "--smtlib", str(smt)]) == 2
    assert "Int only" in capsys.readouterr().err


def test_cli_import_missing_file_is_a_usage_error(tmp_path, capsys):
    assert cli_main(["import", "--smtlib", str(tmp_path / "nope.smt2")]) == 2
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize("solver", KNOWN_SOLVERS)
def test_a_proved_obligation_exits_clean(solver, tmp_path):
    _require(solver)
    """The success case must not look like a tool failure.

    The script used to end in `(get-model)`, which is an error after `unsat` --
    the very result that means "proved". z3 printed `model is not available` and
    exited 1, so a CI step running `z3 obligation.smt2` failed exactly when the
    proof succeeded.
    """
    path = tmp_path / "ob.smt2"
    path.write_text(export_spec(SPEC)[0], encoding="utf-8")
    out = subprocess.run([solver, str(path)], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stdout + out.stderr
    assert out.stdout.strip() == "unsat"
    assert "error" not in (out.stdout + out.stderr).lower()


# --------------------------------------------------------------------------- #
# standards conformance: negative numerals
# --------------------------------------------------------------------------- #


def test_export_never_emits_a_bare_negative_numeral():
    """`-1` is a *symbol* in SMT-LIB 2, not a number.

    z3 accepts it as an extension, so this shipped looking fine and only the
    strict cvc5 in CI rejected it -- `Symbol '-1' not declared as a variable`,
    and the whole script refused. This assertion catches it without needing a
    strict solver on the machine running the tests.
    """
    import re

    for script in export_spec(SPEC) + [export_obligation(DOMAIN, GUARD, SAFETY, 0)]:
        body = script.split("(set-logic")[1]
        assert not re.search(r"[\s(]-\d", body), body


def test_negative_constants_survive_the_round_trip():
    """`(- 65535)` must read back as -65535, not as a variable named '- 65535'."""
    spec = make_spec(
        [atom({"x": -1}, -65535)],
        [atom({"x": -3}, 7)],
        [atom({"x": 1}, -2)],
        name="negatives",
    )
    got = [atom_from_json(a) for a in import_spec(export_spec(spec)[0])["safety"]]
    body = {k: v for k, v in spec.items() if k != "fingerprint"}
    body["safety_index"] = 0
    assert all(_same(a, b) for a, b in zip(got, reconstruct_obligation(body)))


def test_a_negative_coefficient_is_still_read_as_linear():
    """`(* (- 1) x)` is linear. Treating the `(- 1)` term as the variable part
    made it look like a product of two non-constants."""
    text = "(declare-const x Int)(assert (<= (* (- 1) x) 0))"
    got = atom_from_json(import_spec(text)["safety"][0])
    assert got.coeff == {"x": -1}


def test_a_genuine_product_is_still_refused_alongside_negatives():
    """The looser factor handling must not loosen the nonlinear check."""
    text = "(declare-const x Int)(declare-const y Int)(assert (<= (* (- 1) x y) 0))"
    with pytest.raises(SmtLibUnsupported) as exc:
        import_spec(text)
    assert "nonlinear" in str(exc.value)
