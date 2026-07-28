# Honest scope

What `certkit` proves, and what it does not. This is the most important document in the repository:
a verification tool that is vague about its boundary is worse than no tool, because it converts an
open question into false confidence.

## What an `ACCEPTED` verdict means

Exactly this:

> For every assignment of rational values to the variables that satisfies every `domain` atom and
> every `guard` atom, at least one `safety` atom also holds — and here is the arithmetic.

The mechanism: `ACCEPTED` means that for each safety conjunct *i*, the system
`domain ∧ guard ∧ ¬safety[i]` was shown infeasible by a Farkas certificate — nonnegative multipliers
whose weighted sum cancels every variable and leaves an impossible constant.

Two consequences worth stating separately:

- **It is a proof over the rationals, which is stronger than you need.** The integers are a subset of
  the rationals, so rational infeasibility implies integer infeasibility. A verdict over ℚ covers
  every integer input.
- **It is a proof over the domain you declared, and silent everywhere else.** The domain is an input,
  not something inferred from your code.

## What it does NOT mean

### It says nothing about your program

certkit checks a relation between symbols. That the relation describes your code is a human
judgement, made when the spec was written, and nothing here verifies it. If you write
`off + len <= 4096` but the code actually computes `off + len + 1`, certkit will happily prove the
wrong thing, correctly.

This is why specs are kept to small integer inequalities: so a reviewer can check the modelling step
by reading, which is the only way it gets checked.

### A refusal is not a disproof

`REFUSED` means *this certificate did not establish the claim*. It does not mean the claim is false.
There are three quite different reasons for a refusal, and the output distinguishes them:

- the multipliers are wrong or malformed;
- no certificate was supplied;
- the claim is genuinely false.

Farkas' lemma is complete for linear rational arithmetic, so a *true* linear claim over ℚ does have a
certificate — but certkit does not search for one, so its inability to show you one proves nothing.

Symmetrically, certkit never certifies a negation. To learn that a guard is genuinely unsound, you
need a witness, which is [`exploit-counter`](https://github.com/nickharris808/exploit-counter)'s job,
not this package's.

### `UNVERIFIED` is not a pass

If you pass `--no-fingerprint`, the certificate is never bound to the spec. The arithmetic may check
out perfectly while the certificate was issued for something else entirely. That reports
`UNVERIFIED`, exits 3, and must not be read as an acceptance.

### Fingerprints detect drift, not forgery

`spec_fingerprint` is a SHA-256 over the canonical spec. It catches the case where a spec changed and
a certificate went stale — the common, accidental, important case.

It is **not** a defence against someone who controls the spec. A deliberate forger edits the spec to
something trivially true and recomputes the fingerprint, and every check passes. There is no
cryptographic identity here and no signature. Soundness against a hostile author rests on a human
reading the relations.

If you need authenticity, sign the spec with something that has a trust root. certkit does not
pretend to be that.

### The fragment is small

Quantifier-free **linear** arithmetic over ordered fields. Specifically not in scope:

| Not supported | Note |
|---|---|
| Nonlinear terms (`x*y`, `x²`) | see `certkit sos` for a *different*, incomplete, method |
| Bitwise operations, shifts, masks | not expressible as linear atoms |
| Machine-word wraparound | atoms are over ℚ; overflow is not modelled |
| Floating-point semantics | no float appears anywhere in the checker |
| Arrays, pointers, aliasing, the heap | no memory model exists here |
| Loops, recursion, control flow | there is no program semantics, only relations |
| Quantifiers | every variable is implicitly universally quantified |

Integer-specific reasoning is also absent. `2x = 1` is infeasible over ℤ but feasible over ℚ, so
certkit will not refute it. Refusals of that shape are expected, not bugs.

### Sum-of-squares is incomplete

`certkit sos` checks a rational identity `scale · target = Σqᵢ²` with `scale > 0`, which proves
`target ≥ 0`. That direction is sound.

The converse fails: a nonnegative polynomial need not admit an SOS decomposition — Motzkin's
polynomial `x⁴y² + x²y⁴ − 3x²y² + 1` is the standard witness. A refusal means "no certificate
supplied, or it did not check", never "the target is negative". Nonnegativity over ℤ, or over a
non-compact domain, is a different question again.

## The trusted computing base

If certkit says `ACCEPTED` and the claim is false, one of these is at fault:

1. **The modelling.** The spec does not describe the code. Not checkable by any tool here.
2. **The checker.** ~400 lines of dependency-free Python, no floats, no solver, no search. Written to
   be read; 174 tests, of which the interesting ones are negative.
3. **Python's `fractions` and `hashlib`.** Standard library.

That is the whole list. It is short on purpose: the *producer* of a certificate can be arbitrarily
complicated and entirely untrusted, because it is not in this list.

## When to use something else

| If you need | Use |
|---|---|
| To know a guard is genuinely unsound, with a witness | [exploit-counter](https://github.com/nickharris808/exploit-counter) |
| Verdicts inside an AI coding agent | [crs-mcp](https://github.com/nickharris808/crs-mcp) |
| To find certificates rather than check them | an LP/SMT solver — emit [`SPEC.md`](SPEC.md) format |
| Nonlinear, bitvector, or heap reasoning | a general SMT solver (z3, cvc5) |
| Whole-program verification of C | a deductive verifier (Frama-C, CBMC) |
| To judge whether a soundness tool is any good | [soundnessbench](https://github.com/nickharris808/soundnessbench) |

## The one-sentence version

certkit proves that a specific linear relation implies another over a domain you declared, using
arithmetic you can check by hand — and it makes no claim whatsoever about whether those relations
describe your program.
