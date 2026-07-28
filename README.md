# certkit

[![ci](https://github.com/nickharris808/certkit/actions/workflows/ci.yml/badge.svg)](https://github.com/nickharris808/certkit/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/certkit.svg)](https://pypi.org/project/certkit/)
[![Python](https://img.shields.io/pypi/pyversions/certkit.svg)](https://pypi.org/project/certkit/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](pyproject.toml)

**A certificate format for machine-checked program admission, and an independent checker for it.**

The checker imports nothing outside the Python standard library. No solver, no search, no
floating-point arithmetic. It fits in an afternoon of reading, which is the entire point: you should
not have to trust the tool that *produced* a proof in order to believe the proof.

```
pip install certkit
```

## 30-second quickstart

The example ships inside the package, so this works immediately after `pip install` — no repository
checkout, no files to create:

```bash
certkit demo
```
```
certkit demo -- CVE-2014-0160 (Heartbleed) shape
  claim: guard `19 + payload <= record_len`
         implies `3 + payload <= record_len` for payload in [0, 65535]

  valid certificate  -> ACCEPTED
      obligation 0: ok
  forged certificate -> REFUSED
      obligation 0: FAIL -- non-strict combination needs const > 0, got -65535

  As expected: the real certificate checks out and the forgery does not.
```

To check your own files:

```bash
certkit check --spec my.spec.json --cert my.cert.json
```

Exit codes are part of the contract: `0` accepted, `1` refused, `2` usage error. A refusal means
*not proven* — never *proven false*.

## The worked example

The shipped example is the CVE-2014-0160 (Heartbleed) shape. The claim is that the guard
`19 + payload <= record_len` implies the raw access bound `3 + payload <= record_len` for every
payload in `[0, 65535]`.

```python
from certkit import atom, make_spec, check_certificate

domain = [atom({"payload": -1}), atom({"payload": 1}, -65535)]   # 0 <= payload <= 65535
guard  = [atom({"payload": 1, "record_len": -1}, 19)]            # 19 + payload <= record_len
safety = [atom({"payload": 1, "record_len": -1}, 3)]             #  3 + payload <= record_len

spec = make_spec(domain, guard, safety, name="heartbleed")

cert = {
    "schema": "certkit/farkas/v1",
    "spec_fingerprint": spec["fingerprint"],
    "obligations": [{"multipliers": {"2": 1, "3": 1}}],
}

report = check_certificate(spec, cert)
assert report            # truthy when every obligation is refuted
```

Those multipliers are the whole proof. Atom 2 is the guard (`payload - record_len + 19 <= 0`) and
atom 3 is the negated safety property (`-payload + record_len - 3 < 0`). Add them with weight 1
each: every variable cancels and `16 < 0` remains, which is absurd — so no counterexample exists.

## How it works

A **Farkas certificate** witnesses that a conjunction of linear atoms is unsatisfiable. It is a
vector of nonnegative multipliers such that the weighted atoms sum to a contradiction: all variables
cancel and the surviving constant is impossible.

Soundness in one line: if every `L_i <= 0` and every `m_i >= 0`, then `sum(m_i * L_i) <= 0`
necessarily — so if the multipliers make the variables cancel and leave a positive constant, the
system has no solution.

Because the integers are a subset of the rationals, rational infeasibility implies integer
infeasibility. The converse does not hold, which is exactly why a failure to find a certificate is
not a proof of satisfiability. This checker refuses; it does not certify the negation.

Finding the multipliers is somebody else's problem. This package contains no search. That asymmetry
is what makes proof-carrying verification useful — the producer can be arbitrarily clever and
entirely untrusted, because checking is cheap and auditable.

## Reconstruction: why a forged certificate fails

A naive checker reads the atoms out of the certificate and verifies the multipliers against *those*
atoms. That is close to worthless — a certificate carrying an easy, unrelated system plus a valid
refutation of it would pass while proving nothing about your program.

`certkit` ignores any atoms a certificate carries. It rebuilds the obligation from the
independently-supplied spec:

```
system := domain AND guard AND NOT(safety)
```

and lets the certificate supply only the multipliers. The certificate is additionally bound to the
spec by a SHA-256 fingerprint.

That fingerprint detects drift and accidental mismatch. It is **not** a defence against a deliberate
forger, who would simply recompute it over an edited spec. Soundness ultimately rests on a human
having read the spec's relations — which are small integer inequalities, deliberately small enough
to read. We would rather say that plainly than imply a guarantee the mechanism does not provide.

## Sum-of-squares certificates

For nonlinear obligations `target(x) >= 0`, the analogous certificate is a rational identity
`scale * target == sum(q_i^2)` with `scale > 0`:

```bash
certkit sos --cert my-sos-cert.json
```

Every square is nonnegative and the scale is positive, so the target is nonnegative. The checker
re-multiplies the polynomials and verifies the identity exactly over the rationals — a perturbed
certificate fails because every monomial coefficient must cancel to zero. There is no tolerance to
tune.

**Scope, honestly:** sum-of-squares is incomplete. A nonnegative polynomial need not admit an SOS
decomposition (Motzkin's polynomial is the standard witness), and nonnegativity over the integers or
over a non-compact domain is a different question. A refusal means "no certificate supplied, or it
did not check" — never "the target is negative".

## What this package is not

- **Not a solver.** It never searches for a proof. Bring your own producer.
- **Not a completeness oracle.** Refusal is not disproof.
- **Not a defence against a forger who controls the spec.** See above.
- **Not a whole-program verifier.** It checks the obligation you hand it, over the domain you
  declare. Whether that obligation captures your real safety property is your judgement, and the
  spec is kept small so you can exercise it.

## Where certificates come from

This package deliberately contains no producer. That is what keeps the trusted base small enough to
read in an afternoon — and it means you need something upstream to *find* the multipliers.

For small problems, any LP or SMT solver will do; the format is documented in [`SPEC.md`](SPEC.md)
precisely so you can emit it from whatever you already run. Deciding obligations over full
machine-word domains without enumerating them needs a solver-free elimination procedure, which is
not part of this package and is available commercially.

The split is the point: **the checker is free and always will be**, because a certificate you cannot
independently verify is worth nothing. What costs money is producing certificates at scale.

## API

| Function | Purpose |
|---|---|
| `atom(coeff, const, strict)` | build a linear atom `sum(coeff*var) + const <= 0` |
| `negate(a)` | logical negation; flips coefficients, constant, and strictness |
| `verify_farkas(atoms, multipliers)` | check a refutation; returns a truthy result with `.reason` |
| `verify_sos(cert)` | check a rational sum-of-squares identity |
| `make_spec(domain, guard, safety, name)` | build a spec with its fingerprint |
| `check_certificate(spec, cert)` | full check across every safety conjunct |
| `reconstruct_obligation(spec)` | rebuild `domain AND guard AND NOT(safety)` |

## Tests

```bash
pip install -e ".[dev]"
pytest
```

58 tests. The negative cases are the interesting ones: hostile indices, negative and float
multipliers, non-cancelling variables, feasible systems, tampered specs, cross-bound certificates,
and a forged certificate that carries its own easy system. A checker that accepts a valid
certificate is table stakes; one that rejects near-misses is the product.

---

## The closed core

These packages are the *checking* half. They deliberately contain no proof search, which is what keeps
them small enough to audit — and it means something upstream has to produce certificates.

For obligations over full machine-word domains, enumeration does not scale and a decision procedure
that does not enumerate is required: solver-free elimination emitting replayable certificates. That
engine, the repair synthesiser that derives a minimal guard from a refutation, and the evolutionary
search that drives them are **not** in this repository and are available commercially.

The split is deliberate and permanent. **The checker is free and always will be** — a certificate you
cannot independently verify is worth nothing, so charging for verification would defeat the format.
What costs money is *producing* certificates at scale.

## License

Apache-2.0. Copying is the point — this is a format we want adopted, not a moat.
