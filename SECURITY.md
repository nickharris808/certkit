# Security policy

## Reporting a vulnerability

Email **nickharris808@users.noreply.github.com** with `[certkit-security]` in the subject.
Please do not open a public issue for a soundness bug until it is fixed.

Expect an acknowledgement within a few days. This is a small project maintained by one person, so
please be patient with fixes; acknowledgement will be prompt even when the fix is not.

## What counts as a vulnerability here

The severity order is unusual for a Python package, and deliberate:

| Severity | Class | Why |
|---|---|---|
| **Highest** | **A soundness bug** — the checker accepts something false, or a tool reports a verdict it did not establish | The entire portfolio exists to be trustworthy. A checker that can be made to accept a bad proof is worse than no checker, because it converts an open question into false confidence. |
| High | A verdict that is confidently wrong in either direction, including a refusal reported as proof of the negation | Refusal means *not proven*, never *proven false*. |
| Medium | A crash on attacker-controlled input, where a refusal was documented | Specs and certificates are untrusted input. "Reject, don't raise" is a stated rule. |
| Low | Denial of service through resource exhaustion | The tools cap their own work and refuse; a way past a cap is worth reporting. |

**Please report soundness bugs even if you cannot produce an exploit.** A spec and certificate pair
that is accepted when it should be refused is a complete report on its own.

## What is out of scope

- **That a spec does not describe your program.** These tools check relations between symbols; that
  the relations model your code is a human judgement made when the spec was written. No tool here
  can catch it, and `SCOPE.md` says so.
- **Forgery by someone who controls the spec.** The fingerprint detects drift, not forgery — a
  forger edits the spec and recomputes it. This is documented, not a defect.
- **Incompleteness.** Failing to find or check a proof that exists is a limitation, not a
  vulnerability. Sum-of-squares in particular is incomplete by construction.
- Vulnerabilities in Python itself or in a development dependency, unless this project's use of it
  is what creates the exposure.

## Scope

This policy covers the published packages and artefacts of this portfolio:
`certkit`, `exploit-counter`, `crs-mcp`, `soundnessbench`, `certkit-action`,
`pytest-mutation-verified`, and the `cve-proof-corpus` dataset and `certkit-demo` Space.
