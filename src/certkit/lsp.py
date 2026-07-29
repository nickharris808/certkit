"""A Language Server for certkit specifications.

    certkit lsp          # speaks LSP over stdio

Verification that only happens in CI arrives after you have stopped thinking
about the guard. This moves it to the moment you write it: open a
``*.spec.json`` in any editor with an LSP client and the diagnostics appear as
you type.

What it reports, and nothing beyond it:

* **Structure** -- a spec that does not match the published JSON Schema, with the
  offending field named.
* **Binding** -- when a ``*.cert.json`` sits beside the spec, the verdict of
  actually checking it, with the binding check on. A certificate carrying no
  fingerprint is refused here exactly as ``certkit check`` refuses it: the editor
  and the gate must not disagree about what a file means.
* **Modelling smells** -- a variable that appears in the guard or the safety
  property but is bounded by nothing in the domain. That is not an error and is
  not reported as one. An unbounded variable makes the claim *stronger* (the
  obligation must hold for every value it could take) and therefore harder to
  prove, which is worth knowing when a guard you believe is correct will not
  verify.

What it does **not** do is guess. There is no producer here, so it never offers
to "fix" a guard, and it never reports a spec as correct -- the absence of
diagnostics means nothing was found wrong with the *file*, which is a much
smaller claim than the guard being right. That distinction is the whole reason
the checker exists, and an editor is exactly where it would be tempting to blur.

The implementation is standard library only: a JSON-RPC framing loop over stdin
and stdout. No pygls, no dependency, and small enough to read in one sitting --
the same property the checker itself is built around.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import unquote, urlparse

from .cert import ACCEPTED, check_certificate
from .schemas import load_schema

__all__ = ["diagnostics_for", "uri_to_path", "serve", "main", "ERROR", "WARNING", "INFORMATION"]

ERROR = 1
WARNING = 2
INFORMATION = 3
HINT = 4


def uri_to_path(uri: str) -> Path | None:
    """``file://`` URI to a path. Returns ``None`` for anything else.

    A server that guessed at an unfamiliar scheme would end up reading a file the
    editor never mentioned.

    On Windows an editor sends ``file:///c%3A/x/a.spec.json``, whose parsed path
    is ``/c:/x/a.spec.json`` -- a leading slash before the drive letter that
    makes the path invalid. It is stripped here. The Windows CI matrix is what
    surfaced this; a POSIX-only test would have passed forever.
    """
    parsed = urlparse(uri)
    if parsed.scheme != "file":
        return None
    path = unquote(parsed.path)
    if re.match(r"^/[A-Za-z]:", path):
        path = path[1:]
    return Path(path)


def _line_of(text: str, needle: str) -> int:
    """The zero-based line where ``needle`` first appears, or 0.

    Diagnostics need a position and JSON has no line information once parsed.
    Searching the raw text is approximate; being one line off is better than
    dropping the diagnostic, and it never changes what is reported.
    """
    for i, line in enumerate(text.splitlines()):
        if needle in line:
            return i
    return 0


def _diagnostic(line: int, severity: int, message: str, code: str) -> dict[str, Any]:
    return {
        "range": {
            "start": {"line": line, "character": 0},
            "end": {"line": line, "character": 200},
        },
        "severity": severity,
        "source": "certkit",
        "code": code,
        "message": message,
    }


def _validate_structure(spec: Any, text: str) -> list[dict[str, Any]]:
    """Shape checks that do not need a JSON Schema library.

    `jsonschema` is a development dependency of this package and must not become
    a runtime one, so the structural rules the schema encodes are re-stated here
    for the handful of fields an editor can usefully complain about.
    """
    out: list[dict[str, Any]] = []
    if not isinstance(spec, dict):
        return [_diagnostic(0, ERROR, "a spec must be a JSON object", "spec/not-object")]

    schema_id = load_schema("certkit/spec/v1").get("properties", {}).get("schema", {})
    expected = schema_id.get("const", "certkit/spec/v1")
    if spec.get("schema") != expected:
        out.append(
            _diagnostic(
                _line_of(text, '"schema"'),
                ERROR,
                f"expected schema {expected!r}, found {spec.get('schema')!r}",
                "spec/schema",
            )
        )

    for field in ("domain", "guard", "safety"):
        value = spec.get(field)
        if value is None:
            if field not in spec:
                # Absent is fine for domain and guard (an empty conjunction), and
                # fatal for safety.
                if field == "safety":
                    out.append(
                        _diagnostic(
                            0, ERROR, "a spec needs at least one safety conjunct", "spec/safety"
                        )
                    )
                continue
            # Present but null is not an empty list. The checker refuses it, so
            # the editor must not show a clean file. The stress suite found this:
            # `"guard": null` produced no diagnostic at all.
            out.append(
                _diagnostic(
                    _line_of(text, f'"{field}"'),
                    ERROR,
                    f"'{field}' is null. Use [] for an empty conjunction, or remove the key.",
                    f"spec/{field}",
                )
            )
            continue
        if not isinstance(value, list):
            out.append(
                _diagnostic(
                    _line_of(text, f'"{field}"'),
                    ERROR,
                    f"'{field}' must be a list of atoms, found {type(value).__name__}",
                    f"spec/{field}",
                )
            )
            continue
        for i, atom in enumerate(value):
            if not isinstance(atom, dict) or not isinstance(atom.get("coeff"), dict):
                out.append(
                    _diagnostic(
                        _line_of(text, f'"{field}"'),
                        ERROR,
                        f"{field}[{i}] is not an atom: it needs a 'coeff' object",
                        f"spec/{field}/atom",
                    )
                )
                continue
            const = atom.get("const")
            if const is not None and not (isinstance(const, list) and len(const) == 2):
                out.append(
                    _diagnostic(
                        _line_of(text, f'"{field}"'),
                        ERROR,
                        f"{field}[{i}] 'const' must be [numerator, denominator]",
                        f"spec/{field}/const",
                    )
                )
            for var, pair in atom["coeff"].items():
                out.extend(_pair_problems(pair, text, var, f"{field}[{i}] coefficient for {var!r}"))
            if const is not None:
                out.extend(_pair_problems(const, text, f'"{field}"', f"{field}[{i}] 'const'"))
    if not spec.get("safety"):
        out.append(
            _diagnostic(0, ERROR, "a spec needs at least one safety conjunct", "spec/safety")
        )
    return out


def _pair_problems(pair: Any, text: str, needle: str, label: str) -> list[dict[str, Any]]:
    """Validate one ``[numerator, denominator]`` pair.

    Checking only the *shape* was not enough, and the stress suite is what showed
    it: ``[NaN, 1]``, ``[Infinity, 1]``, ``[[[1]], 1]`` and ``[1, 0]`` are all
    two-element lists, so the editor reported a clean file for four specs the
    checker refuses outright. An editor that disagrees with the gate is worse
    than an editor with no diagnostics.
    """
    if not (isinstance(pair, list) and len(pair) == 2):
        return [
            _diagnostic(
                _line_of(text, needle),
                ERROR,
                f"{label} must be [numerator, denominator]",
                "spec/pair",
            )
        ]
    numerator, denominator = pair
    for part, what in ((numerator, "numerator"), (denominator, "denominator")):
        if isinstance(part, bool) or not isinstance(part, int):
            shown = "a nested list" if isinstance(part, list) else repr(part)
            return [
                _diagnostic(
                    _line_of(text, needle),
                    ERROR,
                    f"{label}: the {what} must be a whole number, found {shown}. "
                    "Rationals travel as exact integer pairs precisely so that no "
                    "verdict depends on float formatting.",
                    "spec/pair",
                )
            ]
    if denominator == 0:
        return [
            _diagnostic(
                _line_of(text, needle),
                ERROR,
                f"{label} has a zero denominator",
                "spec/zero-denominator",
            )
        ]
    return []


def _unbounded_variables(spec: dict[str, Any]) -> set[str]:
    """Variables the guard or safety mentions that the domain never constrains."""

    def names(field: str) -> set[str]:
        found: set[str] = set()
        for atom in spec.get(field) or []:
            if isinstance(atom, dict) and isinstance(atom.get("coeff"), dict):
                found |= {v for v, c in atom["coeff"].items() if c != [0, 1]}
        return found

    return (names("guard") | names("safety")) - names("domain")


def diagnostics_for(text: str, path: Path | None = None) -> list[dict[str, Any]]:
    """Every diagnostic for one spec document.

    An empty list means nothing was found wrong with the *file*. It is not a
    statement that the guard is right, and this server never makes one.
    """
    try:
        spec = json.loads(text)
    except json.JSONDecodeError as exc:
        return [_diagnostic(max(exc.lineno - 1, 0), ERROR, f"invalid JSON: {exc.msg}", "json")]

    out = _validate_structure(spec, text)
    if any(d["severity"] == ERROR for d in out):
        # Structure first. Reporting a verdict for a spec that does not parse
        # would be a verdict about something other than what the author wrote.
        return out

    for var in sorted(_unbounded_variables(spec)):
        out.append(
            _diagnostic(
                _line_of(text, var),
                INFORMATION,
                f"{var!r} is used but never bounded by the domain, so the obligation must "
                "hold for every value it could take -- including values your program cannot "
                "produce. That makes the claim stronger, not weaker, and it makes the "
                "obligation harder to refute. If a guard you believe is correct will not "
                "verify, a missing domain bound is the first thing to check.",
                "spec/unbounded",
            )
        )

    cert_path = _certificate_beside(path)
    if cert_path is not None:
        try:
            cert = json.loads(cert_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            out.append(
                _diagnostic(0, WARNING, f"cannot read {cert_path.name}: {exc}", "cert/unreadable")
            )
            return out

        report = check_certificate(spec, cert)
        if report.verdict == ACCEPTED:
            out.append(
                _diagnostic(
                    0,
                    INFORMATION,
                    f"{cert_path.name} verifies against this spec ({len(report.obligations)} "
                    "obligation(s)). This says the certificate proves the guard implies safety "
                    "over the declared domain -- not that the domain describes your program.",
                    "cert/accepted",
                )
            )
        else:
            for o in report.obligations:
                if not o["ok"]:
                    out.append(
                        _diagnostic(
                            _line_of(text, '"safety"'),
                            WARNING,
                            f"{cert_path.name} does not refute obligation {o['index']}: "
                            f"{o['reason']}. This is not a proof that the guard is wrong.",
                            "cert/refused",
                        )
                    )
            if not report.obligations:
                out.append(
                    _diagnostic(0, WARNING, f"{cert_path.name}: {report.reason}", "cert/refused")
                )
    return out


def _certificate_beside(path: Path | None) -> Path | None:
    if path is None:
        return None
    name = path.name
    if name.endswith(".spec.json"):
        candidate = path.with_name(name[: -len(".spec.json")] + ".cert.json")
    else:
        candidate = path.with_suffix(".cert.json")
    return candidate if candidate.is_file() else None


# --------------------------------------------------------------------------- #
# the protocol
# --------------------------------------------------------------------------- #


def _read_message(stream: BinaryIO) -> dict[str, Any] | None:
    """Read one LSP message. Returns ``None`` at end of input."""
    length = 0
    while True:
        line = stream.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            break
        if line.lower().startswith(b"content-length:"):
            try:
                length = int(line.split(b":", 1)[1])
            except ValueError:
                return None
    if length <= 0:
        return None
    body = stream.read(length)
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        # A malformed frame is dropped rather than crashing the server; the
        # editor is free to send another.
        return {}


def _write_message(stream: BinaryIO, payload: dict[str, Any]) -> None:
    body = json.dumps(payload).encode("utf-8")
    stream.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii"))
    stream.write(body)
    stream.flush()


CAPABILITIES = {
    "textDocumentSync": {"openClose": True, "change": 1, "save": True},
    "positionEncoding": "utf-16",
}


def serve(stdin: BinaryIO, stdout: BinaryIO) -> int:
    """Run the server loop until the client closes the connection."""
    documents: dict[str, str] = {}

    def publish(uri: str) -> None:
        text = documents.get(uri, "")
        path = uri_to_path(uri)
        _write_message(
            stdout,
            {
                "jsonrpc": "2.0",
                "method": "textDocument/publishDiagnostics",
                "params": {"uri": uri, "diagnostics": diagnostics_for(text, path)},
            },
        )

    while True:
        message = _read_message(stdin)
        if message is None:
            return 0
        if not message:
            continue

        method = message.get("method")
        msg_id = message.get("id")
        params = message.get("params") or {}

        if method == "initialize":
            _write_message(
                stdout,
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "capabilities": CAPABILITIES,
                        "serverInfo": {"name": "certkit-lsp", "version": _version()},
                    },
                },
            )
        elif method == "shutdown":
            _write_message(stdout, {"jsonrpc": "2.0", "id": msg_id, "result": None})
        elif method == "exit":
            return 0
        elif method == "textDocument/didOpen":
            doc = params.get("textDocument", {})
            documents[doc.get("uri", "")] = doc.get("text", "")
            publish(doc.get("uri", ""))
        elif method == "textDocument/didChange":
            uri = params.get("textDocument", {}).get("uri", "")
            changes = params.get("contentChanges") or []
            if changes:
                # Full-document sync (the capability advertised above), so the
                # last change carries the whole file.
                documents[uri] = changes[-1].get("text", "")
            publish(uri)
        elif method == "textDocument/didSave":
            publish(params.get("textDocument", {}).get("uri", ""))
        elif method == "textDocument/didClose":
            documents.pop(params.get("textDocument", {}).get("uri", ""), None)
        elif msg_id is not None:
            # An unimplemented request must be answered, or the editor waits
            # forever. Answering "method not found" is the honest reply.
            _write_message(
                stdout,
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": f"method not found: {method}"},
                },
            )


def _version() -> str:
    from . import __version__

    return __version__


def main(argv: Any = None) -> int:
    return serve(sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    raise SystemExit(main())
