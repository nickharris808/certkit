# Tutorial: from a C bounds check to a CI gate

One continuous example, start to finish. A real bounds check, the spec that describes it, the
certificate that proves it, the counterexample when it is wrong, and the CI job that blocks the
merge.

Every command below was run to produce the output shown. Nothing is illustrative.

**Time: about fifteen minutes.** You need Python 3.9+ and nothing else.

```bash
pip install "certkit@git+https://github.com/nickharris808/certkit@main" \
            "exploit-counter@git+https://github.com/nickharris808/exploit-counter@main"
```

---

## 1. The code

Here is a function that reads a slice out of a fixed 4096-byte buffer.

```c
#define BUFSZ 4096
static unsigned char buf[BUFSZ];

int read_slice(size_t off, size_t len, unsigned char *dst) {
    if (off + len <= BUFSZ) {          // <-- the guard
        memcpy(dst, buf + off, len);   // <-- the access it protects
        return 0;
    }
    return -1;
}
```

Three things matter, and they are the three things a spec records:

| | In the code | As a relation |
|---|---|---|
| **Domain** | what the caller can pass | `0 <= off <= 4095`, `0 <= len <= 4095` |
| **Guard** | the `if` | `off + len <= 4096` |
| **Safety** | what `memcpy` needs | `off + len <= 4096` |

The claim to prove is: **within the domain, the guard implies safety.** Note that the guard and the
safety property are not always the same relation — here they happen to coincide, which is what
"correct" looks like. Step 4 shows what happens when they do not.

## 2. Write it down

You do not have to hand-write JSON atoms. `certkit init` takes the relations as you would say them:

```bash
certkit init \
  --domain "0 <= len"  --domain "len <= 4095" \
  --domain "0 <= off"  --domain "off <= 4095" \
  --guard  "off + len <= 4096" \
  --safety "off + len <= 4096" \
  --name read_bounds \
  -o read_bounds.spec.json
```
```
wrote read_bounds.spec.json
Next: find multipliers that refute each of the 1 obligation(s), then
  certkit check --spec read_bounds.spec.json --cert your.cert.json
```

The file it wrote is the canonical form — exact rationals as `[numerator, denominator]` pairs, plus
a SHA-256 fingerprint over the whole spec. You can read it, and you should at least once.

## 3. Prove it

A **certificate** is a set of nonnegative weights, one per atom, such that the weighted sum of

```
domain AND guard AND NOT(safety)
```

cancels every variable and leaves an impossible constant. If that system has no solution, then no
input satisfies the guard while violating safety — which is exactly the claim.

certkit contains no search, so you supply the weights. For a relation this small you can read them
off. The obligation is `domain ++ guard ++ [NOT safety]`, so the atoms are numbered:

```
[0]  -len <= 0            (from 0 <= len)
[1]  len - 4095 <= 0
[2]  -off <= 0
[3]  off - 4095 <= 0
[4]  len + off - 4096 <= 0    (the guard)
[5]  -len - off + 4096 < 0    (the negated safety property)
```

Atoms 4 and 5 are exact opposites, so weight 1 on each cancels everything:

```json
{
  "schema": "certkit/farkas/v1",
  "spec_fingerprint": "<copy the fingerprint from read_bounds.spec.json>",
  "obligations": [{"multipliers": {"4": 1, "5": 1}}]
}
```

```bash
certkit check --spec read_bounds.spec.json --cert read_bounds.cert.json
```
```
ACCEPTED: read_bounds
  [ok ] obligation 0
```

Exit code 0. To see *why* rather than just *whether*:

```bash
certkit explain --spec read_bounds.spec.json --cert read_bounds.cert.json
```
```
Obligation 0: is this system satisfiable?

    [0]  -len <= 0
    [1]  len - 4095 <= 0
    [2]  -off <= 0
    [3]  off - 4095 <= 0
    [4]  len + off - 4096 <= 0
    [5]  -len - off + 4096 < 0

  Multiply each atom by its nonnegative weight and add:

    1 * [4]    (len + off - 4096 <= 0)
    1 * [5]    (-len - off + 4096 < 0)

  Every variable cancels: len, off all sum to 0.

  What remains is:  0 < 0

  At least one atom was strict, so the sum is strict: 0 < 0.
  That is false, so the system has no solution. Within the declared
  domain, the guard implies the safety property.
```

That is the entire proof. `0 < 0` is false, so there is no counterexample.

## 4. Now break it

Suppose someone writes `<=` where they meant `<`, and the guard becomes `off + len <= 4097`.

```bash
certkit init \
  --domain "0 <= len"  --domain "len <= 4095" \
  --domain "0 <= off"  --domain "off <= 4095" \
  --guard  "off + len <= 4097" \
  --safety "off + len <= 4096" \
  --name read_bounds_offbyone \
  -o offbyone.spec.json
```

There is now no certificate to be found, because the claim is false. The useful question is *how*
false — and that is a different tool:

```bash
exploit-counter count --spec offbyone.spec.json --box "len=0:4095,off=0:4095"
```
```
read_bounds_offbyone: over-acceptance = 4094 state(s)  [exact, exact]
  domain volume: 16777216
  per-draw hit probability: 0.000244021
  expected uniform draws to hit: 4,098
```

Exit code 1, so this drops into CI as a gate on its own.

Read that last line carefully, because it is the point of the whole portfolio. A uniform fuzzer needs
about **4,098** draws to stumble onto this. A test suite with a hundred random cases will pass, every
time, for years. "We fuzzed it and found nothing" is consistent with both *correct* and *we did not
look hard enough*, and here it happens to be the second.

Not an estimate, either: 4,094 is an exact integer count over all 16,777,216 points of the declared
domain.

For the concrete input to put in a regression test, ask for a counterexample:

```python
from crs_mcp import certify_guard

v = certify_guard(
    domain=[
        {"coeff": {"len": -1}},
        {"coeff": {"len": 1}, "const": -4095},
        {"coeff": {"off": -1}},
        {"coeff": {"off": 1}, "const": -4095},
    ],
    guard=[{"coeff": {"off": 1, "len": 1}, "const": -4097}],
    safety=[{"coeff": {"off": 1, "len": 1}, "const": -4096}],
    box={"len": [0, 4095], "off": [0, 4095]},
)
print(v.verdict)  # PROVEN_UNSOUND
print(v.summary)
```
```
The guard admits 4,094 state(s) the safety property forbids (out of 16,777,216).
Example: {'off': 2, 'len': 4095}.
```

`off=2, len=4095` gives `off + len = 4097`, which the buggy guard accepts and the buffer cannot
survive. That is a test case, not a hypothesis.

## 5. Gate it in CI

Commit the spec and its certificate next to the code they describe, and re-check them on every push:

```yaml
name: proofs
on: [push, pull_request]

jobs:
  certkit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write        # only needed for the SARIF upload below
    steps:
      - uses: actions/checkout@v4
      - uses: nickharris808/certkit-action@main
        with:
          spec: certs/*.spec.json
          certkit-ref: main          # pin to a commit SHA for reproducibility
          sarif: certkit.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: certkit.sarif
```

Now, if someone edits the guard without updating the proof, the fingerprint stops matching and the
job fails with `certificate is bound to a different spec`. If someone edits both, the multipliers
stop cancelling and the job fails with the arithmetic. Either way the merge is blocked, and the
finding shows up in the Security tab rather than in a log nobody opens.

## 6. What you have, and what you do not

You have proved: **for every one of the 16,777,216 integer points where `0 <= off <= 4095` and
`0 <= len <= 4095`, the guard `off + len <= 4096` implies `off + len <= 4096`.**

You have not proved:

- that `off` and `len` in the running program actually stay inside that domain — you *declared* it;
- that this relation is the right safety property for `memcpy` — you chose it;
- anything about the C code at all. certkit checks a relation, and a human decided that relation
  describes the code. That is why specs are kept small enough to read.

[`SCOPE.md`](SCOPE.md) states this boundary in full. It is worth ten minutes before you rely on any
of this.

## Where to go next

| | |
|---|---|
| [`SCOPE.md`](SCOPE.md) | exactly what a verdict does and does not establish |
| [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) | the errors you will actually hit, and what fixes them |
| [`SPEC.md`](SPEC.md) | the on-disk format, if you want to emit it from your own solver |
| [exploit-counter](https://github.com/nickharris808/exploit-counter) | if a guard is unsound, exactly how many states escape |
| [crs-mcp](https://github.com/nickharris808/crs-mcp) | the same verdicts, as tools an AI agent can call |
| [soundnessbench](https://github.com/nickharris808/soundnessbench) | how to tell whether a soundness tool is any good |
| [the browser demo](https://huggingface.co/spaces/nickh007/certkit-demo) | all of the above, no install |
