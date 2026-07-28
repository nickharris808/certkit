# Changelog

All notable changes to this package. Format follows [Keep a Changelog](https://keepachangelog.com/);
versioning is [semantic](https://semver.org/).

## [0.3.0]

### Added
- **SMT-LIB 2 bridge.** `certkit export` writes each obligation as a script z3 or cvc5 can check
  (`unsat` = the guard implies safety); `certkit import` reads one back. Export is total; import is
  deliberately partial and refuses anything outside quantifier-free linear integer arithmetic
  **by name** — a silent partial import would produce a spec proving a weaker theorem than the file
  stated. A dedicated CI job runs the differential against z3 (and cvc5 where available) and fails
  if no solver is present, so the cross-check cannot degrade into a silent skip.
- `certkit schema --format certkit/spec/v1` prints the **JSON Schema** for either format, so other
  tools can emit certkit documents mechanically instead of from prose. Schemas ship in the wheel.
- `certkit check --format {text,json,sarif,junit,markdown}`. SARIF feeds GitHub code scanning;
  JUnit is rendered natively by most CI systems.
- `certkit.report.render()` — one module emits every format, so a refusal is worded identically in
  the log, the Security tab, and a PR comment. `certkit-action` now delegates to it.
- `py.typed`: the public API is typed for downstream consumers.

### Changed
- **`check_certificate` is no longer quadratic in the number of safety conjuncts.** The shared
  `domain ++ guard` prefix is parsed once rather than once per obligation. Measured: 400 conjuncts
  over 200 atoms went from **668 ms to 8.5 ms** (78x), and the parse count from 240,400 to 601.
- A malformed spec atom now refuses **every** obligation rather than only the one being built. It
  was already a refusal-with-reason, never a traceback; the change is that a spec which cannot be
  rebuilt is reported as such consistently. No verdict becomes more permissive.

## [0.2.0]

**Breaking.** This release removed every path where the checker returned a verdict it had not
earned. If you pinned `0.1.0`, read this before upgrading — the changes are deliberate, and each
one turns a silent pass into a loud refusal.

| Change | 0.1.0 | 0.2.0 | What to do |
|---|---|---|---|
| `check_certificate(..., require_fingerprint=False)` | `report.ok is True` | `report.ok is False`, `verdict == "UNVERIFIED"` | An unbound certificate proves nothing about your spec. Bind it, or treat exit 3 as a failure. |
| `certkit check --no-fingerprint` | exit `0` | exit **`3`** | Treat non-zero as "do not merge". |
| `CheckReport.ok` | stored field | property: `obligations_ok and binding_verified` | Read `.verdict` for the three-way answer. |
| Malformed spec atoms | raised `ZeroDivisionError` / `TypeError` | refusal with a reason | Nothing; the traceback contradicted the documented "reject, don't raise". |

### Added
- Third verdict `UNVERIFIED`, with `CheckReport.verdict`, `.obligations_ok`, `.binding_verified`.
- `certkit explain` — renders the refutation arithmetic: which atoms, which weights, what cancels.
- `certkit init` — scaffolds a spec from written relations (`"19 + payload <= record_len"`) instead
  of hand-written JSON atoms.

## [0.1.0]
- First release: the atom type, Farkas and sum-of-squares checking, spec fingerprinting,
  `certkit check`, `certkit sos`, `certkit demo`.
