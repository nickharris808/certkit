"""Certificate container, obligation reconstruction, and the top-level check.

The security-relevant idea in this module is **reconstruction**. A naive checker
reads the atoms out of the certificate and verifies the multipliers against
*those* atoms. That is close to worthless: a certificate that carries an easy,
unrelated system together with a valid refutation of it would pass, while proving
nothing about the program you care about.

So the checker here ignores any atoms the certificate carries and rebuilds the
obligation from an independently supplied specification:

    system := domain AND guard AND NOT(safety)

If that system is infeasible, then within the domain the guard implies safety --
which is the property actually being claimed. The certificate is only permitted
to supply the *multipliers*.

The certificate is additionally bound to the specification by a fingerprint over
the canonical serialisation of the spec. This detects drift and accidental
mismatch. It is explicitly **not** a defence against a deliberate forger, who
would simply recompute the fingerprint over an edited spec -- soundness rests on
a human having audited the spec's relations, which are small enough to read.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from .atoms import Atom, atom_from_json, atom_to_json, negate
from .farkas import FarkasResult, verify_farkas

__all__ = [
    "CERT_SCHEMA",
    "SPEC_SCHEMA",
    "ACCEPTED",
    "REFUSED",
    "UNVERIFIED",
    "fingerprint",
    "reconstruct_obligation",
    "check_certificate",
    "CheckReport",
]

CERT_SCHEMA = "certkit/farkas/v1"
SPEC_SCHEMA = "certkit/spec/v1"

#: Every obligation was refuted **and** the certificate was bound to this spec.
ACCEPTED = "ACCEPTED"
#: At least one obligation was not refuted.
REFUSED = "REFUSED"
#: The arithmetic checked out, but a required precondition was never established
#: -- so no claim is being made. This is not a pass.
UNVERIFIED = "UNVERIFIED"


def fingerprint(spec: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical JSON of a specification body."""
    payload = json.dumps(spec, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _parse_spec_atoms(spec: Mapping[str, Any]) -> tuple[list[Atom], list[Atom]]:
    """Parse a spec's atoms once: the ``domain ++ guard`` prefix, and safety.

    Every obligation shares the same prefix and differs only in which safety
    conjunct is negated onto the end. Parsing is the expensive part -- each atom
    builds a Fraction per coefficient -- so :func:`check_certificate` parses once
    here and reuses the result across all conjuncts, rather than re-parsing the
    whole spec per obligation.
    """
    prefix: list[Atom] = [atom_from_json(a) for a in spec.get("domain", [])]
    prefix += [atom_from_json(a) for a in spec.get("guard", [])]
    safety: list[Atom] = [atom_from_json(a) for a in spec.get("safety", [])]
    return prefix, safety


def reconstruct_obligation(spec: Mapping[str, Any]) -> list[Atom]:
    """Rebuild ``domain AND guard AND NOT(safety)`` from a specification.

    ``safety`` is a conjunction; its negation is a disjunction, which is not
    expressible as a single atom list. The spec therefore names which safety
    conjunct is under refutation via ``safety_index``, and one obligation is
    formed per conjunct. Callers wanting the whole property iterate over the
    indices -- see :func:`check_certificate`.
    """
    prefix, safety = _parse_spec_atoms(spec)
    idx = int(spec.get("safety_index", 0))
    if not safety:
        raise ValueError("spec has no safety conjuncts")
    if idx < 0 or idx >= len(safety):
        raise ValueError(f"safety_index {idx} out of range")
    return [*prefix, negate(safety[idx])]


class CheckReport:
    """Aggregate result across every safety conjunct of a specification.

    Two things must hold before this reports success, and they are tracked
    separately because they can fail separately:

    ``obligations_ok``
        every safety conjunct was refuted by the supplied multipliers.
    ``binding_verified``
        the certificate was cryptographically bound to *this* spec.

    ``ok`` is the conjunction. A certificate whose arithmetic is impeccable but
    which was never bound to the spec proves nothing about the spec, so it
    reports :data:`UNVERIFIED` -- never ``ACCEPTED``, and never silently ``ok``.
    """

    __slots__ = ("obligations", "reason", "obligations_ok", "binding_verified")

    def __init__(
        self,
        ok: bool,
        obligations: list[dict[str, Any]],
        reason: str = "",
        *,
        binding_verified: bool = True,
    ) -> None:
        self.obligations_ok = ok
        self.binding_verified = binding_verified
        self.obligations = obligations
        self.reason = reason

    @property
    def ok(self) -> bool:
        """True only when the proof checks *and* it is bound to this spec."""
        return self.obligations_ok and self.binding_verified

    @property
    def verdict(self) -> str:
        """:data:`ACCEPTED`, :data:`REFUSED`, or :data:`UNVERIFIED`."""
        if not self.obligations_ok:
            return REFUSED
        if not self.binding_verified:
            return UNVERIFIED
        return ACCEPTED

    def __bool__(self) -> bool:
        return self.ok

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "ok": self.ok,
            "obligations_ok": self.obligations_ok,
            "binding_verified": self.binding_verified,
            "reason": self.reason,
            "obligations": self.obligations,
        }

    def __repr__(self) -> str:
        return (
            f"CheckReport(verdict={self.verdict!r}, n={len(self.obligations)}, "
            f"reason={self.reason!r})"
        )


def check_certificate(
    spec: Mapping[str, Any],
    cert: Mapping[str, Any],
    *,
    require_fingerprint: bool = True,
) -> CheckReport:
    """Verify that ``cert`` proves the guard implies safety over the domain.

    One obligation is checked per safety conjunct. Every obligation must be
    refuted, **and** the certificate must be bound to this spec, for the report
    to be ``ok``.

    Passing ``require_fingerprint=False`` skips the binding check. It does not
    make the result an acceptance: the report comes back with
    ``binding_verified=False`` and ``verdict == UNVERIFIED``, because a
    certificate that was never tied to this spec has not been shown to say
    anything about this spec. The escape hatch is for authoring workflows where
    the fingerprint has not been computed yet, not for relaxing the verdict.
    """
    if cert.get("schema") != CERT_SCHEMA:
        return CheckReport(False, [], f"unexpected certificate schema {cert.get('schema')!r}")
    if spec.get("schema") != SPEC_SCHEMA:
        return CheckReport(False, [], f"unexpected spec schema {spec.get('schema')!r}")

    body = {k: v for k, v in spec.items() if k != "fingerprint"}
    actual = fingerprint(body)

    binding_verified = True
    binding_note = ""

    if require_fingerprint:
        declared = spec.get("fingerprint")
        if declared is not None and declared != actual:
            return CheckReport(False, [], "spec fingerprint does not match its own body")
        bound = cert.get("spec_fingerprint")
        if bound is None:
            return CheckReport(False, [], "certificate is not bound to a spec fingerprint")
        if bound != actual:
            return CheckReport(False, [], "certificate is bound to a different spec")
    else:
        binding_verified = False
        binding_note = (
            "TRUST ANCHOR ABSENT: fingerprint checking was disabled, so this certificate "
            "was never tied to the supplied spec. The multipliers below were checked "
            "against the spec's own reconstructed atoms, but nothing establishes that "
            "this certificate was issued for this spec. Not an acceptance."
        )

    safety = spec.get("safety", [])
    if not isinstance(safety, Sequence) or isinstance(safety, (str, bytes)):
        return CheckReport(False, [], f"spec 'safety' must be a list, got {type(safety).__name__}")
    if not safety:
        return CheckReport(False, [], "spec has no safety conjuncts")

    per_obligation = cert.get("obligations")
    if not isinstance(per_obligation, list) or len(per_obligation) != len(safety):
        return CheckReport(
            False,
            [],
            f"certificate supplies {len(per_obligation) if isinstance(per_obligation, list) else 0}"
            f" obligation(s); spec requires {len(safety)}",
        )

    # Parse the spec's atoms once rather than once per obligation. Every
    # obligation is `domain ++ guard ++ [negate(safety[i])]`, so only the last
    # element differs; re-parsing the shared prefix k times made the check
    # quadratic in the number of safety conjuncts.
    #
    # A spec is attacker-controlled input like any other, so a malformed atom --
    # a zero denominator, an Infinity coefficient, a string where an object
    # belongs -- is a refusal with a reason, never a traceback out of the
    # checker. Parsing up front means one bad atom fails every obligation, which
    # is correct: the spec as a whole could not be rebuilt.
    try:
        prefix, safety_atoms = _parse_spec_atoms(body)
    except (ValueError, TypeError, KeyError, AttributeError, ArithmeticError) as exc:
        reason = f"malformed spec atom: {type(exc).__name__}: {exc}"
        return CheckReport(
            False,
            [{"index": i, "ok": False, "reason": reason} for i in range(len(safety))],
            reason,
            binding_verified=binding_verified,
        )

    # One list, reused across obligations: only the final slot changes. Safe
    # because verify_farkas reads the sequence and never retains it.
    obligation: list[Atom] = [*prefix, negate(safety_atoms[0])]

    results: list[dict[str, Any]] = []
    all_ok = True
    for i in range(len(safety)):
        obligation[-1] = negate(safety_atoms[i])
        atoms = obligation

        entry = per_obligation[i]
        multipliers = entry.get("multipliers") if isinstance(entry, Mapping) else None
        if not isinstance(multipliers, Mapping):
            results.append({"index": i, "ok": False, "reason": "missing multipliers"})
            all_ok = False
            continue

        res: FarkasResult = verify_farkas(atoms, multipliers)
        results.append({"index": i, "ok": bool(res), "reason": res.reason})
        all_ok = all_ok and bool(res)

    if not all_ok:
        reason = "one or more obligations failed"
        if binding_note:
            reason = f"{reason}; also: {binding_note}"
    else:
        reason = binding_note

    return CheckReport(all_ok, results, reason, binding_verified=binding_verified)


def make_spec(
    domain: Sequence[Atom],
    guard: Sequence[Atom],
    safety: Sequence[Atom],
    name: str = "unnamed",
) -> dict[str, Any]:
    """Build a specification dict with its fingerprint filled in."""
    body: dict[str, Any] = {
        "schema": SPEC_SCHEMA,
        "name": name,
        "domain": [atom_to_json(a) for a in domain],
        "guard": [atom_to_json(a) for a in guard],
        "safety": [atom_to_json(a) for a in safety],
    }
    body["fingerprint"] = fingerprint(dict(body.items()))
    return body
