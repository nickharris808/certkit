"""``certkit`` command-line entry point.

Exit codes are part of the contract, because this is meant to run in CI:

    0  ACCEPTED   -- every obligation refuted, and the certificate is bound to
                     this spec
    1  REFUSED    -- at least one obligation not refuted, or malformed input
    2  usage error (missing file, unreadable JSON)
    3  UNVERIFIED -- the arithmetic checked out but a required precondition was
                     never established (``--no-fingerprint``). No claim is made.

Note that exit 1 means "not proven", never "proven false". A refusal is a
refusal. Exit 3 is neither: it is the tool declining to certify something it
did not fully check, and CI should treat it as a failure, not a pass.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .cert import UNVERIFIED, check_certificate
from .report import FORMATS, render
from .schemas import SCHEMA_FILES, load_schema
from .sos import verify_sos


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def example_path(name: str) -> Path:
    """Path to a bundled example file, wherever the package is installed."""
    return Path(__file__).resolve().parent / "examples" / name


def _demo() -> int:
    """Run the bundled Heartbleed example: one valid certificate, one forged.

    This needs no files on disk and no repository checkout, so the documented
    quickstart works immediately after `pip install certkit`.
    """
    spec = _load(example_path("heartbleed.spec.json"))
    good = _load(example_path("heartbleed.cert.json"))
    forged = _load(example_path("heartbleed.forged.json"))

    print("certkit demo -- CVE-2014-0160 (Heartbleed) shape")
    print("  claim: guard `19 + payload <= record_len`")
    print("         implies `3 + payload <= record_len` for payload in [0, 65535]")
    print()

    ok = check_certificate(spec, good)
    print(f"  valid certificate  -> {ok.verdict}")
    for obligation in ok.obligations:
        detail = f" -- {obligation['reason']}" if obligation["reason"] else ""
        print(
            f"      obligation {obligation['index']}: "
            f"{'ok' if obligation['ok'] else 'FAIL'}{detail}"
        )

    bad = check_certificate(spec, forged)
    print(f"  forged certificate -> {bad.verdict}")
    for obligation in bad.obligations:
        detail = f" -- {obligation['reason']}" if obligation["reason"] else ""
        print(
            f"      obligation {obligation['index']}: "
            f"{'ok' if obligation['ok'] else 'FAIL'}{detail}"
        )

    print()
    if ok and not bad:
        print("  As expected: the real certificate checks out and the forgery does not.")
        return 0
    print("  UNEXPECTED: the demo did not behave as documented.")
    return 1


def main(argv: Any = None) -> int:
    parser = argparse.ArgumentParser(
        prog="certkit",
        description="Independently re-check a program-admission certificate.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="check a Farkas certificate against a spec")
    p_check.add_argument("--spec", required=True, type=Path)
    p_check.add_argument("--cert", required=True, type=Path)
    p_check.add_argument(
        "--no-fingerprint",
        action="store_true",
        help=(
            "skip the spec/certificate binding check. The result can then only ever be "
            "UNVERIFIED (exit 3), never ACCEPTED -- an unbound certificate has not been "
            "shown to be about this spec"
        ),
    )
    p_check.add_argument("--json", action="store_true", help="shorthand for --format json")
    p_check.add_argument(
        "--format",
        choices=FORMATS,
        default="text",
        help=(
            "output format. 'sarif' feeds GitHub code scanning; 'junit' is rendered "
            "natively by most CI systems; 'markdown' suits a PR comment."
        ),
    )

    p_explain = sub.add_parser(
        "explain",
        help="show the refutation arithmetic in prose (which atoms, which weights, what cancels)",
    )
    p_explain.add_argument("--spec", required=True, type=Path)
    p_explain.add_argument("--cert", required=True, type=Path)

    p_init = sub.add_parser(
        "init",
        help="scaffold a spec from written relations, e.g. '19 + payload <= record_len'",
    )
    p_init.add_argument(
        "--domain",
        action="append",
        default=[],
        metavar="RELATION",
        help="a bound on the attacker's inputs, e.g. '0 <= payload'. Repeatable.",
    )
    p_init.add_argument(
        "--guard",
        action="append",
        default=[],
        metavar="RELATION",
        help="the check your code performs, e.g. '19 + payload <= record_len'. Repeatable.",
    )
    p_init.add_argument(
        "--safety",
        action="append",
        default=[],
        metavar="RELATION",
        help="the property that must hold, e.g. '3 + payload <= record_len'. Repeatable.",
    )
    p_init.add_argument("--name", default="unnamed")
    p_init.add_argument("-o", "--out", type=Path, help="write here instead of stdout")

    p_schema = sub.add_parser(
        "schema",
        help="print the JSON Schema for a certkit format, so other tools can emit it",
    )
    p_schema.add_argument(
        "--format",
        dest="schema_name",
        default="certkit/spec/v1",
        choices=sorted(SCHEMA_FILES),
    )

    p_sos = sub.add_parser("sos", help="check a sum-of-squares certificate")
    p_sos.add_argument("--cert", required=True, type=Path)

    sub.add_parser(
        "demo",
        help="run the bundled example (needs no files; works straight from pip install)",
    )

    args = parser.parse_args(argv)

    if args.command == "demo":
        return _demo()

    if args.command == "check":
        try:
            spec = _load(args.spec)
            cert = _load(args.cert)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        report = check_certificate(spec, cert, require_fingerprint=not args.no_fingerprint)

        fmt = "json" if args.json else args.format
        # SARIF anchors findings at a file, so pass the spec path rather than the
        # spec's own name -- a code-scanning alert has to point somewhere real.
        label = str(args.spec) if fmt == "sarif" else spec.get("name", "<unnamed>")
        print(render(report, fmt, name=label))
        if report.verdict == UNVERIFIED:
            return 3
        return 0 if report.ok else 1

    if args.command == "explain":
        try:
            spec = _load(args.spec)
            cert = _load(args.cert)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        from .explain import explain_certificate

        print(explain_certificate(spec, cert))
        # Explaining is not deciding. Exit status still reflects the verdict, so
        # this can be dropped into a script without changing its meaning.
        report = check_certificate(spec, cert)
        if report.verdict == UNVERIFIED:
            return 3
        return 0 if report.ok else 1

    if args.command == "init":
        from .scaffold import RelationSyntaxError, build_spec

        try:
            spec = build_spec(args.domain, args.guard, args.safety, name=args.name)
        except RelationSyntaxError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        text = json.dumps(spec, indent=2)
        if args.out:
            try:
                args.out.write_text(text + "\n", encoding="utf-8")
            except OSError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            n = len(spec["safety"])
            print(f"wrote {args.out}")
            print(
                f"Next: find multipliers that refute each of the {n} obligation(s), then\n"
                f"  certkit check --spec {args.out} --cert your.cert.json"
            )
        else:
            print(text)
        return 0

    if args.command == "schema":
        print(json.dumps(load_schema(args.schema_name), indent=2))
        return 0

    if args.command == "sos":
        try:
            cert = _load(args.cert)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        ok = verify_sos(cert)
        print("ACCEPTED" if ok else "REFUSED")
        return 0 if ok else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
