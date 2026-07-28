# certkit

[![ci](https://github.com/nickharris808/certkit/actions/workflows/ci.yml/badge.svg)](https://github.com/nickharris808/certkit/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![status](https://img.shields.io/badge/status-pre--release-orange.svg)](#install)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](pyproject.toml)

**A certificate format for machine-checked program admission, and an independent checker for it.**

> **Try it now, no install:** [open the browser demo](https://huggingface.co/spaces/nickh007/certkit-demo) and press **Load a forgery** — the checker refuses it, client-side.

The checker imports nothing outside the Python standard library. No solver, no search, no
floating-point arithmetic. It fits in an afternoon of reading, which is the entire point: you should
not have to trust the tool that *produced* a proof in order to believe the proof.

<a id="install"></a>
```bash
pip install "certkit@git+https://github.com/nickharris808/certkit@main"
```

> **Pre-release.** The PyPI name is reserved and publication is imminent; until then the line above
> is the working install. It is tested in CI on Linux, macOS, and Windows.

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

**New here?** [`TUTORIAL.md`](TUTORIAL.md) walks a real C bounds check all the way to a CI gate in
about fifteen minutes — including what it looks like when the guard is wrong.

## CLI reference

```
certkit {check,explain,init,sos,demo}
```

| Command | What it does |
|---|---|
| `certkit demo` | Run the bundled Heartbleed example: one valid certificate, one forged. No files needed. |
| `certkit init` | Scaffold a spec from written relations, so you never hand-write JSON atoms. |
| `certkit check` | Decide a spec/certificate pair. This is the one CI runs. |
| `certkit explain` | Print the refutation arithmetic — which atoms, which weights, what cancels. |
| `certkit sos` | Check a rational sum-of-squares certificate. |
| `certkit schema` | Print the JSON Schema for a format, so other tools can emit it. |

### `certkit init`

```bash
certkit init \
  --domain "0 <= payload" --domain "payload <= 65535" \
  --guard  "19 + payload <= record_len" \
  --safety "3 + payload <= record_len" \
  --name heartbleed -o heartbleed.spec.json
```

| Flag | Meaning |
|---|---|
| `--domain RELATION` | A bound on the attacker's inputs. Repeatable. |
| `--guard RELATION` | The check your code performs. Repeatable. |
| `--safety RELATION` | The property that must hold. Repeatable; one obligation each. |
| `--name`, `-o/--out` | Spec name; output path (stdout if omitted). |

Accepts `<=`, `<`, `>=`, `>`, integer coefficients with `*`, and `+`/`-`. Rejects `==` (that is two
atoms — write both), chained comparisons, and anything nonlinear, rather than guessing. Parsing the
relations above reproduces the hand-written bundled spec byte for byte, fingerprint included.

### `certkit check`

| Flag | Meaning |
|---|---|
| `--spec`, `--cert` | The pair to check. Required. |
| `--no-fingerprint` | Skip the binding check. Can only ever yield `UNVERIFIED` (exit 3), never `ACCEPTED`. |
| `--json` | Shorthand for `--format json`. |
| `--format` | `text`, `json`, `sarif`, `junit`, or `markdown`. See below. |

### Output formats

```bash
certkit check --spec my.spec.json --cert my.cert.json --format sarif > certkit.sarif
```

| Format | For |
|---|---|
| `text` | a terminal |
| `json` | scripts; the report verbatim, including `verdict` and `binding_verified` |
| `sarif` | GitHub code scanning — a refusal becomes an alert on the PR |
| `junit` | most CI systems render this natively |
| `markdown` | a PR comment or job summary |

Changing the format never changes the verdict or the exit code. `UNVERIFIED` is its own level in
every one of them — SARIF rule `certkit/unverified`, a JUnit failure of type `unverified` — because
a format that rendered it as a pass would undo the reason the third verdict exists.

### Emitting certkit from your own tool

```bash
certkit schema --format certkit/spec/v1 > spec.schema.json
```

Both formats have a published JSON Schema, shipped inside the wheel and validated in CI against
every bundled example and 200 generated specs. `SPEC.md` explains the format to a person; the schema
explains it to a program.

```python
from certkit.schemas import load_schema, schema_for

load_schema("certkit/farkas/v1")  # by format id
schema_for(my_document)  # by the document's own `schema` field
```

Validating against them needs a JSON Schema library, which is a development dependency here —
`certkit` itself still imports nothing outside the standard library.

### `certkit explain`

Takes the same `--spec` and `--cert`. Prints the arithmetic and **exits with the same status as
`check`**, so dropping it into a script does not launder a refusal into a success.

```
    [2]  payload - record_len + 19 <= 0
    [3]  -payload + record_len - 3 < 0

  Multiply each atom by its nonnegative weight and add:

    1 * [2]    (payload - record_len + 19 <= 0)
    1 * [3]    (-payload + record_len - 3 < 0)

  Every variable cancels: payload, record_len all sum to 0.

  What remains is:  16 < 0
```

## Three verdicts, and why there are three

| Verdict | Exit | Meaning |
|---|---|---|
| `ACCEPTED` | 0 | Every obligation was refuted **and** the certificate is bound to this spec. |
| `REFUSED` | 1 | At least one obligation was not refuted, or the input was malformed. |
| `UNVERIFIED` | 3 | The arithmetic checked out, but a required precondition was never established. **Not a pass.** |

`UNVERIFIED` exists because of `--no-fingerprint`. That flag skips the check binding the certificate
to the spec — useful while authoring, when the fingerprint has not been computed yet. But a
certificate that was never tied to this spec has not been shown to say anything *about* this spec, so
reporting it as accepted would be a pass on input the checker did not fully validate. It now reports
`UNVERIFIED` and exits 3, and the reason line says `TRUST ANCHOR ABSENT` in those words.

In the API the same distinction is two separate booleans, because they fail separately:

```python
report = check_certificate(spec, cert, require_fingerprint=False)
report.obligations_ok  # True  -- the multipliers really do refute the obligation
report.binding_verified  # False -- but nothing ties this certificate to this spec
report.ok  # False -- so the overall answer is no
report.verdict  # 'UNVERIFIED'
```

A refusal means *not proven* — never *proven false*. So does an `UNVERIFIED`.

## The worked example

The shipped example is the CVE-2014-0160 (Heartbleed) shape. The claim is that the guard
`19 + payload <= record_len` implies the raw access bound `3 + payload <= record_len` for every
payload in `[0, 65535]`.

```python
from certkit import atom, make_spec, check_certificate

domain = [atom({"payload": -1}), atom({"payload": 1}, -65535)]  # 0 <= payload <= 65535
guard = [atom({"payload": 1, "record_len": -1}, 19)]  # 19 + payload <= record_len
safety = [atom({"payload": 1, "record_len": -1}, 3)]  #  3 + payload <= record_len

spec = make_spec(domain, guard, safety, name="heartbleed")

cert = {
    "schema": "certkit/farkas/v1",
    "spec_fingerprint": spec["fingerprint"],
    "obligations": [{"multipliers": {"2": 1, "3": 1}}],
}

report = check_certificate(spec, cert)
assert report  # truthy when every obligation is refuted
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

`check_certificate` returns a `CheckReport` with `.verdict`, `.ok`, `.obligations_ok`,
`.binding_verified`, `.reason`, and `.obligations`. It never raises on malformed input — a spec is
attacker-controlled just like a certificate, so a zero denominator or an `Infinity` coefficient is a
refusal carrying a reason, not a traceback.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

174 tests. The negative cases are the interesting ones: hostile indices, negative and float
multipliers, non-cancelling variables, feasible systems, tampered specs, cross-bound certificates,
and a forged certificate that carries its own easy system. A checker that accepts a valid
certificate is table stakes; one that rejects near-misses is the product.

`tests/test_adversarial.py` is the permanent guard against one specific failure — the checker saying
`ACCEPTED` on something it did not fully check. Its oracle is *no input may produce a
confident-looking answer that is wrong*, and it covers malformed, empty, enormous, and
out-of-distribution input, plus metamorphic relations (scaling every multiplier by any *k* > 0 must
preserve validity; scaling by 0 must destroy it) and the CLI exit-code contract.

## The rest of the toolkit

| | |
|---|---|
| **[certkit](https://github.com/nickharris808/certkit)** | the certificate format and the independent checker |
| **[exploit-counter](https://github.com/nickharris808/exploit-counter)** | if a guard is unsound, exactly how many states escape |
| **[crs-mcp](https://github.com/nickharris808/crs-mcp)** | the verdict surface AI coding agents call, over MCP |
| **[soundnessbench](https://github.com/nickharris808/soundnessbench)** | the benchmark that grades all of the above |
| **[certkit-action](https://github.com/nickharris808/certkit-action)** | run the check in your CI |
| **[pytest-mutation-verified](https://github.com/nickharris808/pytest-mutation-verified)** | prove your regression test can actually fail |
| **[cve-proof-corpus](https://huggingface.co/datasets/nickh007/cve-proof-corpus)** | six real CVEs with machine-checkable proofs |
| **[Try it in your browser](https://huggingface.co/spaces/nickh007/certkit-demo)** | no install; watch a forgery get refused |

## Documentation

| | |
|---|---|
| [`TUTORIAL.md`](TUTORIAL.md) | a real C bounds check to a CI gate, end to end |
| [`SCOPE.md`](SCOPE.md) | what a verdict proves, and what it does not |
| [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) | every error string, and what fixes it |
| [`SPEC.md`](SPEC.md) | the on-disk format, for emitting it from your own solver |

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
