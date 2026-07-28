"""``certkit`` command-line entry point.

Exit codes are part of the contract, because this is meant to run in CI:

    0  every obligation refuted -- the guard implies safety over the domain
    1  at least one obligation not refuted, or the certificate is malformed
    2  usage error (missing file, unreadable JSON)

Note that exit 1 means "not proven", never "proven false". A refusal is a
refusal.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .cert import check_certificate
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
    print(f"  valid certificate  -> {'ACCEPTED' if ok else 'REFUSED'}")
    for obligation in ok.obligations:
        detail = f" -- {obligation['reason']}" if obligation["reason"] else ""
        print(
            f"      obligation {obligation['index']}: "
            f"{'ok' if obligation['ok'] else 'FAIL'}{detail}"
        )

    bad = check_certificate(spec, forged)
    print(f"  forged certificate -> {'ACCEPTED' if bad else 'REFUSED'}")
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
        help="skip spec/certificate binding (for local experimentation only)",
    )
    p_check.add_argument("--json", action="store_true", help="emit machine-readable output")

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

        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            status = "ACCEPTED" if report.ok else "REFUSED"
            print(f"{status}: {spec.get('name', '<unnamed>')}")
            if report.reason:
                print(f"  reason: {report.reason}")
            for ob in report.obligations:
                mark = "ok " if ob["ok"] else "FAIL"
                detail = f" -- {ob['reason']}" if ob["reason"] else ""
                print(f"  [{mark}] obligation {ob['index']}{detail}")
        return 0 if report.ok else 1

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
