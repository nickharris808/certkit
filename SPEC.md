# The certkit certificate format, v1

This document is the normative description of the on-disk format. It is deliberately small. If you
want to write your own checker in another language, this page plus an exact-rational arithmetic
library is everything you need — that is the intended outcome.

All numbers are exact rationals encoded as `[numerator, denominator]` integer pairs. **Decimal and
floating-point encodings are not permitted anywhere in this format.** A rounding error in a proof
checker is a soundness bug, not a precision nuisance.

## 1. Atoms

An atom is a linear relation in canonical form:

```
sum(coeff[v] * v) + const  <= 0        (when strict is false)
sum(coeff[v] * v) + const  <  0        (when strict is true)
```

Every relation is normalised into this one shape so a checker never case-splits on operators.
`x >= 5` becomes `-x + 5 <= 0`; `a < b` becomes `a - b < 0`.

```json
{
  "coeff":  { "payload": [1, 1], "record_len": [-1, 1] },
  "const":  [19, 1],
  "strict": false
}
```

A variable absent from `coeff` has coefficient zero. A coefficient of zero is equivalent to absence,
and checkers should normalise it away so that structurally equal atoms compare equal.

**Negation.** `not (L <= 0)` is `-L < 0`, and `not (L < 0)` is `-L <= 0`. Negation flips every
coefficient, the constant, and the strictness flag. This is the only operation in the format where
strictness inverts.

## 2. Specification

A specification states the property being claimed. It is the object a human audits.

```json
{
  "schema": "certkit/spec/v1",
  "name": "heartbleed",
  "domain": [ <atom>, ... ],
  "guard":  [ <atom>, ... ],
  "safety": [ <atom>, ... ],
  "fingerprint": "<64 hex chars>"
}
```

| Field | Meaning |
|---|---|
| `domain` | Conjunction bounding the state space. The claim is made *only* within this domain. |
| `guard` | Conjunction the program enforces before the access. |
| `safety` | Conjunction that must hold. Each conjunct becomes one obligation. |
| `fingerprint` | SHA-256 over the canonical JSON of the spec body, excluding `fingerprint` itself. |

The claim is: **within `domain`, `guard` implies `safety`.**

### Canonical fingerprint

```
sha256( json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8") ).hexdigest()
```

where `body` is the spec object with the `fingerprint` key removed. Key order must be sorted and
separators must be compact so that the digest is independent of serialisation whitespace.

## 3. Obligations

`safety` is a conjunction, so its negation is a disjunction — which is not a single atom list. The
format therefore produces **one obligation per safety conjunct**. Obligation `i` is the atom list:

```
domain  ++  guard  ++  [ negate(safety[i]) ]
```

in exactly that order. **Atom indices in a certificate refer to positions in this reconstructed
list**, not to any list carried by the certificate.

The property holds only if *every* obligation is refuted.

## 4. Farkas certificate

```json
{
  "schema": "certkit/farkas/v1",
  "spec_fingerprint": "<64 hex chars>",
  "obligations": [
    { "multipliers": { "2": 1, "3": 1 } },
    ...
  ]
}
```

`obligations` must have exactly the same length as the spec's `safety` array, in the same order.

`multipliers` maps an atom index to a nonnegative rational weight. Because JSON object keys are
strings, indices are strings; a checker must coerce them. Weights may be encoded as an integer, a
decimal-free string such as `"3/2"`, or a `[num, den]` pair.

### Validity condition

A multiplier vector is valid for an atom list iff all of the following hold:

1. every weight is a nonnegative rational (floats are rejected);
2. every index is an integer within range;
3. at least one weight is nonzero;
4. summing `weight * atom` over all nonzero weights cancels **every** variable coefficient to zero;
5. the surviving constant `c` satisfies:
   - `c >= 0` if any atom used with a nonzero weight is strict, or
   - `c > 0` otherwise.

### Why this is sound

If every `L_i <= 0` and every `m_i >= 0`, then `sum(m_i * L_i) <= 0` necessarily. If the variables
cancel, the left side is the constant `c`, so `c <= 0` must hold. A certificate exhibiting `c > 0`
therefore shows the conjunction has no solution. When a strict atom participates, the combination is
strict, so `c >= 0` already contradicts.

Rational infeasibility implies integer infeasibility, because the integers are a subset of the
rationals. **The converse does not hold** — a system may be integer-infeasible yet rationally
feasible. Absence of a certificate is therefore not a proof of satisfiability.

## 5. Sum-of-squares certificate

For a nonlinear obligation `target(x) >= 0`:

```json
{
  "schema": "certkit/sos/v1",
  "scale": 4,
  "target":  { "2,0": [1, 4] },
  "squares": [ { "1,0": [1, 1] } ]
}
```

A monomial key is a comma-joined exponent vector over the certificate's variable order: `"2,0"` is
`x^2`, `"1,1"` is `x*y`, `"0,0"` is the constant term. A polynomial is a map from monomial to
coefficient.

Valid iff `scale` is a positive integer, `squares` is non-empty with no zero polynomial, and

```
scale * target  ==  sum_i (q_i)^2
```

holds **exactly** — every monomial coefficient of the difference cancels to zero. There is no
tolerance parameter.

Soundness: each square is nonnegative and `scale > 0`, so `target >= 0`.

**Incompleteness.** Sum-of-squares is not complete for nonnegativity. A nonnegative polynomial need
not admit an SOS decomposition — Motzkin's polynomial is the standard counterexample — and
nonnegativity over the integers or over non-compact domains is a separate question. A refusal means
"no certificate, or it did not check", never "the target is negative".

## 6. Checker obligations

A conforming checker **must**:

- reconstruct obligations from the spec and **ignore any atom list carried by the certificate**;
- reject rather than raise on malformed input, out-of-range indices, and wrong types;
- use exact rational arithmetic throughout;
- verify `spec_fingerprint` against a recomputation over the spec body;
- treat a failure to verify as *not proven*, and never report it as *proven false*.

A conforming checker **must not**:

- search for multipliers;
- accept a float anywhere;
- accept a certificate whose obligation count differs from the spec's safety conjunct count.

## 7. Threat model, stated plainly

The fingerprint binds a certificate to a spec. It detects drift, accidental mismatch, and
copy-paste of a certificate between specs.

It is **not** a defence against a deliberate forger, who would edit the spec and recompute the
fingerprint over the edited body. Soundness ultimately rests on a human having read the spec — which
is why the format keeps specs to small integer inequalities. If you did not read the spec, you have
verified that a certificate matches a spec, not that your program is safe.

## 8. Version policy

The schema strings `certkit/spec/v1`, `certkit/farkas/v1`, and `certkit/sos/v1` are exact-match. A
checker encountering an unknown schema must refuse rather than guess. Any change to the validity
conditions above will increment the version.
