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
    "fingerprint",
    "reconstruct_obligation",
    "check_certificate",
    "CheckReport",
]

CERT_SCHEMA = "certkit/farkas/v1"
SPEC_SCHEMA = "certkit/spec/v1"


def fingerprint(spec: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical JSON of a specification body."""
    payload = json.dumps(spec, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def reconstruct_obligation(spec: Mapping[str, Any]) -> list[Atom]:
    """Rebuild ``domain AND guard AND NOT(safety)`` from a specification.

    ``safety`` is a conjunction; its negation is a disjunction, which is not
    expressible as a single atom list. The spec therefore names which safety
    conjunct is under refutation via ``safety_index``, and one obligation is
    formed per conjunct. Callers wanting the whole property iterate over the
    indices -- see :func:`check_certificate`.
    """
    atoms: list[Atom] = [atom_from_json(a) for a in spec.get("domain", [])]
    atoms += [atom_from_json(a) for a in spec.get("guard", [])]

    safety = [atom_from_json(a) for a in spec.get("safety", [])]
    idx = int(spec.get("safety_index", 0))
    if not safety:
        raise ValueError("spec has no safety conjuncts")
    if idx < 0 or idx >= len(safety):
        raise ValueError(f"safety_index {idx} out of range")
    atoms.append(negate(safety[idx]))
    return atoms


class CheckReport:
    """Aggregate result across every safety conjunct of a specification."""

    __slots__ = ("ok", "obligations", "reason")

    def __init__(self, ok: bool, obligations: list[dict[str, Any]], reason: str = "") -> None:
        self.ok = ok
        self.obligations = obligations
        self.reason = reason

    def __bool__(self) -> bool:
        return self.ok

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "reason": self.reason, "obligations": self.obligations}

    def __repr__(self) -> str:
        return f"CheckReport(ok={self.ok!r}, n={len(self.obligations)}, reason={self.reason!r})"


def check_certificate(
    spec: Mapping[str, Any],
    cert: Mapping[str, Any],
    *,
    require_fingerprint: bool = True,
) -> CheckReport:
    """Verify that ``cert`` proves the guard implies safety over the domain.

    One obligation is checked per safety conjunct. Every obligation must be
    refuted for the report to be ``ok``.
    """
    if cert.get("schema") != CERT_SCHEMA:
        return CheckReport(False, [], f"unexpected certificate schema {cert.get('schema')!r}")
    if spec.get("schema") != SPEC_SCHEMA:
        return CheckReport(False, [], f"unexpected spec schema {spec.get('schema')!r}")

    body = {k: v for k, v in spec.items() if k != "fingerprint"}
    actual = fingerprint(body)

    if require_fingerprint:
        declared = spec.get("fingerprint")
        if declared is not None and declared != actual:
            return CheckReport(False, [], "spec fingerprint does not match its own body")
        bound = cert.get("spec_fingerprint")
        if bound is None:
            return CheckReport(False, [], "certificate is not bound to a spec fingerprint")
        if bound != actual:
            return CheckReport(False, [], "certificate is bound to a different spec")

    safety = spec.get("safety", [])
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

    results: list[dict[str, Any]] = []
    all_ok = True
    for i in range(len(safety)):
        sub = dict(body)
        sub["safety_index"] = i
        try:
            atoms = reconstruct_obligation(sub)
        except ValueError as exc:
            results.append({"index": i, "ok": False, "reason": str(exc)})
            all_ok = False
            continue

        entry = per_obligation[i]
        multipliers = entry.get("multipliers") if isinstance(entry, Mapping) else None
        if not isinstance(multipliers, Mapping):
            results.append({"index": i, "ok": False, "reason": "missing multipliers"})
            all_ok = False
            continue

        res: FarkasResult = verify_farkas(atoms, multipliers)
        results.append({"index": i, "ok": bool(res), "reason": res.reason})
        all_ok = all_ok and bool(res)

    return CheckReport(all_ok, results, "" if all_ok else "one or more obligations failed")


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
