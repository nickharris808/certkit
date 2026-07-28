# Troubleshooting

Keyed to the exact strings certkit prints. Every message below was produced by running the code, so
you can search this file for whatever you are looking at.

## Exit codes

| Code | Verdict | Meaning |
|---|---|---|
| 0 | `ACCEPTED` | Proved, and the certificate is bound to this spec. |
| 1 | `REFUSED` | Not proved. **Never** "disproved". |
| 2 | — | Usage error: missing file, unparseable JSON, bad arguments. |
| 3 | `UNVERIFIED` | Arithmetic checked out, but a precondition was not established. Not a pass. |

If you are scripting this, treat anything non-zero as "do not merge". Exit 3 in particular is not a
softer 0.

---

## `variables did not cancel: <names>`

The weighted sum still contains those variables, so it is not a contradiction — it is just another
inequality.

Run `certkit explain --spec <spec> --cert <cert>`. It prints each weighted atom and the running sum,
and the variable that failed to cancel is usually visible immediately: some atom needs a different
weight, or an atom you needed is missing from the multiplier set.

A common cause is weighting only the guard and forgetting the negated safety atom, which is always
the **last** atom in the obligation.

## `non-strict combination needs const > 0, got -65535`

Every variable cancelled — good — but the surviving constant is not impossible. `-65535 <= 0` is
perfectly true, so nothing has been refuted.

You need the sum to land on something false. Either the weights are wrong, or the claim is false.
To find out which, count the gap:

```bash
exploit-counter count --spec my.spec.json --box "payload=0:65535,record_len=0:65535"
```

If that reports a positive over-acceptance, the claim really is false and no certificate exists.
Fix the guard, not the certificate.

## `strict combination needs const >= 0, got -3`

Same situation, with one difference: at least one atom in your combination was strict (`< 0`), so
the sum is strict and `0` is already a contradiction. You need `const >= 0`, not `const > 0`.

## `atom index 99 out of range`

Multiplier indices refer to positions in the *reconstructed* obligation, which is

```
domain ++ guard ++ [negate(safety[i])]
```

concatenated in that order — **not** to anything the certificate carries. With 2 domain atoms and 1
guard atom, valid indices are 0–3, and index 3 is the negated safety atom.

`certkit explain` prints the obligation with indices, which is the fastest way to see the numbering.

## `negative multiplier -1 at index 2`

Farkas multipliers must be nonnegative; that is what makes the argument sound. A negative weight
flips an inequality and would let you "prove" anything.

If you need to subtract an atom, you almost certainly want its negation as a separate atom in the
spec instead.

## `certificate is not bound to a spec fingerprint`

The certificate has no `spec_fingerprint` field. Copy the `fingerprint` value out of the spec file:

```json
{
  "schema": "certkit/farkas/v1",
  "spec_fingerprint": "f273dad14d09578f...",
  "obligations": [{"multipliers": {"2": 1, "3": 1}}]
}
```

## `certificate is bound to a different spec`

The fingerprint does not match this spec. Almost always this means **the spec changed after the
certificate was written** — someone edited a bound or a guard and did not regenerate the proof.

This is the check doing its job. Re-derive the certificate against the current spec. Do not paste in
the new fingerprint without redoing the arithmetic; that defeats the entire mechanism.

## `spec fingerprint does not match its own body`

The spec's own `fingerprint` field disagrees with a hash of the rest of the file — the spec was
hand-edited without updating it. Regenerate with `make_spec(...)`, or delete the `fingerprint` field
and let the checker recompute it.

## `certificate supplies 0 obligation(s); spec requires 1`

One obligation per safety conjunct, in order. A spec with three safety relations needs three entries
in `obligations`, even if some are trivial.

## `unexpected certificate schema 'nope'` / `unexpected spec schema ...`

Certificates need `"schema": "certkit/farkas/v1"` and specs need `"schema": "certkit/spec/v1"`.
Missing entirely is the usual cause.

## `malformed spec atom: ZeroDivisionError: Fraction(1, 0)`

An atom has a zero denominator, e.g. `"const": [1, 0]`. Rational values are `[numerator,
denominator]` pairs and the denominator must be non-zero. `Infinity` and `NaN` are rejected the same
way.

This is a refusal with a reason, not a crash — a spec is attacker-controlled input like anything else.

## `TRUST ANCHOR ABSENT` (exit 3, `UNVERIFIED`)

You passed `--no-fingerprint`. The multipliers checked out, but nothing ties the certificate to this
spec, so no claim is being made about it.

That flag is for authoring, when you have not computed the fingerprint yet. It cannot produce an
acceptance, by design. Re-run without it.

## `no comparison operator in 'foo'` (from `certkit init`)

The relation parser wants one comparison per relation:

```bash
certkit init --guard "19 + payload <= record_len" --safety "3 + payload <= record_len"
```

Supported: `<=`, `<`, `>=`, `>`, integer coefficients with `*`, `+` and `-`.

Not supported, deliberately: `==` (that is two atoms — write both, so the spec says what you mean),
chained comparisons like `0 <= x <= 5` (write two relations), and anything nonlinear.

## `'3 <= 5' has no variables, so it is a constant claim, not a relation`

Every atom must mention at least one variable. A relation between two constants is either trivially
true or trivially false and cannot constrain anything.

---

## Errors from the sibling tools

### `variable 'x' is unbounded below` (exploit-counter)

`box_from_atoms` will not invent a range for a variable no domain atom bounds. An unbounded variable
has no finite model count, so any number over it would be meaningless.

Add a bounding relation, or pass an explicit `default=(lo, hi)` if you are deliberately choosing one.

### `the declared box holds 1 point(s)` (exploit-counter)

A single-point box is refused because "no escapes found" would be true there however unsound the
guard is. Declare a real range. `allow_degenerate=True` if you genuinely mean one point.

### `variable 'x' has an inverted range [10, 2]` (exploit-counter)

Upper bound below lower bound, so the box is empty and any count over it is vacuous. You probably
meant `[2, 10]`.

### `the atoms constrain 'q', which the box does not declare` (exploit-counter)

An atom mentions a variable with no range. Add it to the box, e.g. `q=0:255`.

### `deciding this box would enumerate N points` (crs-mcp)

Above the cap. Note the limit is the **enumerated product**, not the box volume — the widest variable
is solved in closed form and costs nothing, so narrowing *it* will not help. Narrow one of the others.
The message names which variable is the free one.

---

## Still stuck?

- `certkit explain --spec <spec> --cert <cert>` shows the arithmetic rather than the verdict, which
  is usually where the misunderstanding is.
- `certkit demo` runs a known-good pair and a known-bad pair, so you can confirm the install works
  before debugging your own files.
- [`SPEC.md`](SPEC.md) is the format, if you are generating certificates from another tool.
- [`SCOPE.md`](SCOPE.md) is worth re-reading if a verdict is not the one you expected — sometimes the
  tool is right and the claim was not the one you thought you were making.
