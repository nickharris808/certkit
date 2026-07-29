# Architecture

Aimed at two readers: someone deciding whether to trust the checker, and someone about to change it.

## The trust boundary

```
UNTRUSTED                              TRUSTED (and small enough to read)
-------------------------------------  ------------------------------------
whatever produced the certificate      farkas.py    the refutation check
  a solver, an LP, a model, a stranger  atoms.py     the one relation shape
                                        cert.py      reconstruction + binding
the specification                      <- read by a human, checked by nobody
```

The checker trusts nothing the certificate carries. It rebuilds each obligation from the
specification and verifies the multipliers against *that*. What it cannot do is tell you the
specification describes your program; that is the assumption the whole thing rests on, and it is
why specs are a handful of short relations.

## Module map

| Module | Lines (approx.) | Role |
|---|---:|---|
| `atoms.py` | 110 | One canonical shape: `sum(c*v) + k <= 0`, or `< 0` when strict. Exact `Fraction`s. `negate()` is the only place strictness flips. |
| `farkas.py` | 150 | **The core.** Weighted sum of atoms; every variable must cancel; the surviving constant must be impossible. No search, no solver, no floats. |
| `cert.py` | 300 | Obligation reconstruction, fingerprint binding, the three verdicts, and the top-level `check_certificate`. |
| `report.py` | — | Every output format from one place: text, JSON, SARIF, JUnit, markdown. |
| `schemas/` | — | JSON Schema for both formats, plus a loader that needs no third-party package. |
| `smtlib.py` | — | Export to SMT-LIB (total) and import from it (partial, and refuses by name). |
| `scaffold.py` | — | `certkit init`: relations in text to a spec. Rejects what it cannot parse rather than guessing. |
| `explain.py` | — | Prose for a refutation. Never changes a verdict. |
| `lsp.py`, `notebook.py`, `precommit.py`, `cli.py` | — | Frontends. |

## The rule for everything outside the core

**A frontend may change how a verdict is displayed and may never change what it is.**

That is enforced by tests, not convention. The notebook renderer, the SARIF and JUnit writers, the
LSP diagnostics and the pre-commit hook each have a test asserting `UNVERIFIED` does not render as a
pass. If you add a frontend, add that test — it is the one invariant this package cannot lose.

## Why there is no producer

Finding multipliers is search; checking them is arithmetic. Keeping the two apart is what lets the
producer be untrusted. A checker that also produced would still be correct, but the reason to
believe its output would change shape, and the reading effort would grow past the point where
"audit it yourself" is a real suggestion rather than a slogan.

## Data flow of a check

```
spec.json ─┐
           ├─> _parse_spec_atoms()  once, not once per conjunct  (this was quadratic until 0.3.0)
cert.json ─┘         │
                     ├─> for each safety conjunct i:
                     │       obligation = domain ++ guard ++ [negate(safety[i])]
                     │       verify_farkas(obligation, cert.obligations[i].multipliers)
                     │
                     └─> CheckReport(obligations_ok, binding_verified)
                             .verdict -> ACCEPTED | REFUSED | UNVERIFIED
```

`obligations_ok` and `binding_verified` are tracked separately because they fail separately, and
because collapsing them into one boolean is exactly how `--no-fingerprint` used to report a pass.

## Performance shape

Checking is linear in the total size of the obligation and takes microseconds; there is no headroom
worth chasing and no optimisation in the core. The one real defect was structural: reconstruction
re-parsed the shared `domain ++ guard` prefix once per safety conjunct, which is quadratic in
conjunct count. Hoisting the parse took 400 conjuncts over 200 atoms from 668 ms to 8 ms. A
regression test asserts the *parse count*, not the wall clock, so it cannot flake on a loaded runner.

## Extending the format

Both formats have a published JSON Schema (`certkit schema --format certkit/spec/v1`), and the
schema tests run in both directions: real documents must validate, and a *mutated* schema must stop
accepting them, so the schema is load-bearing rather than decorative. If you write a producer,
write it against the schema and the differential vectors in `certkit-js`, not against this prose.
