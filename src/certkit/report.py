"""One place that turns a :class:`CheckReport` into whatever your CI reads.

Every output format is a projection of the same verdict, so they live together:
the moment SARIF lives in the Action and JSON lives in the CLI, they drift, and
a refusal reason ends up worded one way in the log and another in the Security
tab. The oracle for this module is that no format may state a verdict the report
does not carry.

Formats:

    text      what a person reads in a terminal
    json      the report verbatim, for scripts
    sarif     SARIF 2.1.0, for GitHub code scanning and anything else that reads it
    junit     JUnit XML, which almost every CI system renders natively
    markdown  a table, for PR comments and job summaries

`UNVERIFIED` is deliberately not collapsed into either pass or fail anywhere. It
is its own level in SARIF, its own failure type in JUnit, and its own word in the
text and markdown. A format that rendered it as "passed" would undo the whole
point of having a third verdict.
"""

from __future__ import annotations

import json
from typing import Any
from xml.sax.saxutils import escape, quoteattr

from .cert import ACCEPTED, UNVERIFIED, CheckReport

__all__ = ["FORMATS", "render", "sarif_document", "sarif_result", "SARIF_RULES"]

FORMATS = ("text", "json", "sarif", "junit", "markdown")

SARIF_RULES: list[dict[str, Any]] = [
    {
        "id": "certkit/refused",
        "name": "CertificateRefused",
        "shortDescription": {"text": "A proof certificate did not check out"},
        "fullDescription": {
            "text": (
                "The supplied multipliers do not refute the obligation rebuilt from this "
                "spec. The safety property is NOT PROVEN over the declared domain. That "
                "is not the same as the property being false -- certkit refuses, it never "
                "certifies the negation."
            )
        },
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": "Run `certkit explain --spec <spec> --cert <cert>` to see the arithmetic."
        },
    },
    {
        "id": "certkit/unverified",
        "name": "CertificateUnverified",
        "shortDescription": {"text": "A certificate was not bound to its spec"},
        "fullDescription": {
            "text": (
                "The multipliers checked out, but fingerprint verification was disabled, "
                "so nothing establishes that this certificate was issued for this spec. "
                "This is not an acceptance."
            )
        },
        "defaultConfiguration": {"level": "error"},
        "help": {"text": "Re-run without --no-fingerprint, or bind the certificate to the spec."},
    },
]


def _rule_for(verdict: str) -> str:
    return "certkit/unverified" if verdict == UNVERIFIED else "certkit/refused"


def sarif_result(verdict: str, location: str, message: str) -> dict[str, Any]:
    """One SARIF finding, anchored to the spec file it came from."""
    return {
        "ruleId": _rule_for(verdict),
        "level": "error",
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": location},
                    "region": {"startLine": 1},
                }
            }
        ],
    }


def sarif_document(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap findings in a SARIF 2.1.0 run.

    Only the parts GitHub actually consumes are emitted; the full schema is
    enormous and most of it would be noise.
    """
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "certkit",
                        "informationUri": "https://github.com/nickharris808/certkit",
                        "rules": SARIF_RULES,
                    }
                },
                "results": results,
            }
        ],
    }


def _reason_of(report: CheckReport) -> str:
    detail = "; ".join(o["reason"] for o in report.obligations if o.get("reason"))
    return detail or report.reason or report.verdict


def _text(report: CheckReport, name: str) -> str:
    lines = [f"{report.verdict}: {name}"]
    if report.reason:
        lines.append(f"  reason: {report.reason}")
    for ob in report.obligations:
        mark = "ok " if ob["ok"] else "FAIL"
        extra = f" -- {ob['reason']}" if ob.get("reason") else ""
        lines.append(f"  [{mark}] obligation {ob['index']}{extra}")
    if not report.binding_verified and report.obligations_ok:
        lines.append(
            "  NOTE: every obligation was refuted, but with no trust anchor this "
            "is UNVERIFIED, not ACCEPTED. Re-run without --no-fingerprint."
        )
    return "\n".join(lines)


def _markdown(report: CheckReport, name: str) -> str:
    head = ["| item | verdict | detail |", "|---|---|---|"]
    mark = report.verdict if report.verdict == ACCEPTED else f"**{report.verdict}**"
    head.append(f"| `{name}` | {mark} | {_reason_of(report) or 'all obligations discharged'} |")
    return "\n".join(head)


def _junit(report: CheckReport, name: str) -> str:
    """JUnit XML. UNVERIFIED is a distinct failure type, never a pass."""
    failed = 0 if report.ok else 1
    body = ""
    if not report.ok:
        kind = "unverified" if report.verdict == UNVERIFIED else "refused"
        body = (
            f"\n      <failure type={quoteattr(kind)} "
            f"message={quoteattr(_reason_of(report))}>"
            f"{escape(report.verdict)}: {escape(_reason_of(report))}</failure>\n    "
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuites tests="1" failures="{failed}">\n'
        f'  <testsuite name="certkit" tests="1" failures="{failed}">\n'
        f'    <testcase classname="certkit" name={quoteattr(name)}>{body}</testcase>\n'
        "  </testsuite>\n"
        "</testsuites>"
    )


def render(report: CheckReport, fmt: str = "text", *, name: str = "<unnamed>") -> str:
    """Render a report in ``fmt``. Raises on an unknown format rather than guessing."""
    if fmt not in FORMATS:
        raise ValueError(f"unknown format {fmt!r}; choose one of: {', '.join(FORMATS)}")
    if fmt == "json":
        return json.dumps(report.to_dict(), indent=2)
    if fmt == "sarif":
        results = (
            []
            if report.ok
            else [sarif_result(report.verdict, name, f"{report.verdict}: {_reason_of(report)}")]
        )
        return json.dumps(sarif_document(results), indent=2)
    if fmt == "junit":
        return _junit(report, name)
    if fmt == "markdown":
        return _markdown(report, name)
    return _text(report, name)
