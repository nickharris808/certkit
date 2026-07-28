"""The `certkit` pre-commit hook.

pre-commit hands a hook the list of staged files that matched its ``files``
pattern -- here, every ``*.cert.json``. For each one, the hook looks for the
specification beside it and re-checks the pair.

Two decisions worth stating, because both could reasonably have gone the other
way:

**A missing spec is a failure, not a skip.** A certificate with no specification
next to it cannot be checked, and a hook that quietly passed on it would report
"all certificates verified" while verifying none of them. It says which file it
could not find and exits non-zero.

**UNVERIFIED blocks the commit.** Exit 3 from the CLI means the tool declined to
certify. In a gate, "declined to certify" and "refused" have the same
consequence: the proof does not currently hold. Only ACCEPTED passes.
"""

from __future__ import annotations

import sys
from pathlib import Path

from .cert import ACCEPTED, check_certificate
from .cli import _load

__all__ = ["spec_for", "main"]


def spec_for(cert_path: Path) -> Path:
    """The specification a certificate is expected to sit beside.

    ``foo.cert.json`` pairs with ``foo.spec.json``. That is a convention, not a
    format rule, which is why a mismatch is reported rather than guessed around.
    """
    name = cert_path.name
    if name.endswith(".cert.json"):
        return cert_path.with_name(name[: -len(".cert.json")] + ".spec.json")
    return cert_path.with_suffix(".spec.json")


def main(argv: list[str] | None = None) -> int:
    paths = [Path(p) for p in (argv if argv is not None else sys.argv[1:])]
    if not paths:
        # pre-commit passes nothing when no file matched. Nothing to check is not
        # a failure, but say so rather than printing a silent success.
        print("certkit: no certificates staged")
        return 0

    failures = 0
    for cert_path in paths:
        spec_path = spec_for(cert_path)
        if not spec_path.is_file():
            print(
                f"{cert_path}: FAIL -- no specification found at {spec_path}. "
                "A certificate cannot be checked without the spec it is about.",
                file=sys.stderr,
            )
            failures += 1
            continue
        try:
            spec = _load(spec_path)
            cert = _load(cert_path)
        except (OSError, ValueError) as exc:
            print(f"{cert_path}: FAIL -- {exc}", file=sys.stderr)
            failures += 1
            continue

        report = check_certificate(spec, cert)
        if report.verdict == ACCEPTED:
            print(f"{cert_path}: ACCEPTED")
            continue

        failures += 1
        print(f"{cert_path}: {report.verdict} -- {report.reason or 'see below'}", file=sys.stderr)
        for o in report.obligations:
            if not o["ok"]:
                print(f"    obligation {o['index']}: {o['reason']}", file=sys.stderr)

    if failures:
        print(
            f"\ncertkit: {failures} certificate(s) did not verify. "
            "UNVERIFIED counts as a failure here: in a gate, 'declined to certify' "
            "and 'refused' have the same consequence.",
            file=sys.stderr,
        )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
