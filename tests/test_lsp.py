"""The language server.

Two things are being tested: that it speaks the protocol correctly enough for a
real editor, and -- the part that matters -- that moving verification into an
editor does not soften any verdict. An editor is the most tempting place to blur
"nothing was found wrong with this file" into "this guard is fine".
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from certkit.cli import _load, example_path
from certkit.lsp import ERROR, INFORMATION, WARNING, diagnostics_for, uri_to_path

SPEC = _load(example_path("heartbleed.spec.json"))
GOOD = _load(example_path("heartbleed.cert.json"))
FORGED = _load(example_path("heartbleed.forged.json"))


def codes(diags):
    return {d["code"] for d in diags}


def severities(diags):
    return {d["code"]: d["severity"] for d in diags}


# --------------------------------------------------------------------------- #
# diagnostics
# --------------------------------------------------------------------------- #


def test_a_valid_spec_alone_produces_no_errors():
    diags = diagnostics_for(json.dumps(SPEC, indent=2))
    assert not [d for d in diags if d["severity"] == ERROR]


def test_invalid_json_is_reported_at_its_line():
    diags = diagnostics_for('{\n  "schema": "certkit/spec/v1",\n  oops\n}')
    assert codes(diags) == {"json"}
    assert diags[0]["range"]["start"]["line"] >= 1


def test_a_wrong_schema_is_named():
    spec = dict(SPEC, schema="certkit/spec/v99")
    diags = diagnostics_for(json.dumps(spec, indent=2))
    assert "spec/schema" in codes(diags)
    assert "certkit/spec/v99" in " ".join(d["message"] for d in diags)


def test_a_zero_denominator_is_an_error_not_a_hint():
    spec = json.loads(json.dumps(SPEC))
    spec["guard"][0]["coeff"]["payload"] = [1, 0]
    diags = diagnostics_for(json.dumps(spec, indent=2))
    assert severities(diags)["spec/zero-denominator"] == ERROR


def test_a_spec_with_no_safety_conjunct_is_an_error():
    spec = dict(SPEC, safety=[])
    assert "spec/safety" in codes(diagnostics_for(json.dumps(spec, indent=2)))


def test_a_malformed_atom_is_reported_with_its_index():
    spec = json.loads(json.dumps(SPEC))
    spec["guard"] = ["not an atom"]
    diags = diagnostics_for(json.dumps(spec, indent=2))
    assert "spec/guard/atom" in codes(diags)
    assert "guard[0]" in " ".join(d["message"] for d in diags)


def test_structural_errors_suppress_the_verdict(tmp_path):
    """A verdict about a spec that does not parse is a verdict about something
    other than what the author wrote."""
    spec = json.loads(json.dumps(SPEC))
    spec["schema"] = "wrong"
    spec_path = tmp_path / "h.spec.json"
    (tmp_path / "h.cert.json").write_text(json.dumps(GOOD), encoding="utf-8")
    diags = diagnostics_for(json.dumps(spec, indent=2), spec_path)
    assert codes(diags) == {"spec/schema"}


def test_an_unbounded_variable_is_information_not_an_error():
    """It is allowed. Reporting it as an error would be inventing a rule the
    format does not have."""
    spec = dict(SPEC, domain=[])
    diags = diagnostics_for(json.dumps(spec, indent=2))
    assert severities(diags)["spec/unbounded"] == INFORMATION


# --------------------------------------------------------------------------- #
# the certificate beside the spec
# --------------------------------------------------------------------------- #


def _pair(tmp_path, cert):
    spec_path = tmp_path / "h.spec.json"
    (tmp_path / "h.cert.json").write_text(json.dumps(cert), encoding="utf-8")
    return spec_path


def test_a_verifying_certificate_is_reported_with_its_boundary(tmp_path):
    diags = diagnostics_for(json.dumps(SPEC, indent=2), _pair(tmp_path, GOOD))
    assert "cert/accepted" in codes(diags)
    message = " ".join(d["message"] for d in diags)
    assert "not that the domain describes your program" in message


def test_an_accepted_certificate_is_information_and_never_silence(tmp_path):
    diags = diagnostics_for(json.dumps(SPEC, indent=2), _pair(tmp_path, GOOD))
    assert severities(diags)["cert/accepted"] == INFORMATION


def test_a_forged_certificate_is_a_warning_that_says_what_it_is_not(tmp_path):
    diags = diagnostics_for(json.dumps(SPEC, indent=2), _pair(tmp_path, FORGED))
    assert severities(diags)["cert/refused"] == WARNING
    assert "not a proof that the guard is wrong" in " ".join(d["message"] for d in diags)


def test_an_unbound_certificate_is_refused_exactly_as_the_gate_refuses_it(tmp_path):
    """The editor and `certkit check` must not disagree about what a file means.

    With the binding check on -- which is what CI runs -- a certificate carrying
    no fingerprint is REFUSED, not UNVERIFIED. The server used to have a branch
    for UNVERIFIED that could never fire; unreachable code that looks like it
    handles a case is worse than no code."""
    unbound = {k: v for k, v in GOOD.items() if k != "spec_fingerprint"}
    diags = diagnostics_for(json.dumps(SPEC, indent=2), _pair(tmp_path, unbound))
    assert severities(diags)["cert/refused"] == WARNING
    assert "not bound" in " ".join(d["message"] for d in diags)


def test_an_unreadable_certificate_is_reported_rather_than_ignored(tmp_path):
    spec_path = tmp_path / "h.spec.json"
    (tmp_path / "h.cert.json").write_text("{not json", encoding="utf-8")
    assert "cert/unreadable" in codes(diagnostics_for(json.dumps(SPEC, indent=2), spec_path))


def test_no_certificate_beside_the_spec_means_no_verdict(tmp_path):
    """Absence of a certificate is not a failure. It is also not a pass, and the
    server says nothing about it either way."""
    diags = diagnostics_for(json.dumps(SPEC, indent=2), tmp_path / "h.spec.json")
    assert not [c for c in codes(diags) if c.startswith("cert/")]


def test_the_server_never_tells_you_a_guard_is_correct(tmp_path):
    """The one claim it must not make. Even with a verifying certificate beside
    the spec, the message says what was established and what was not."""
    for path in (None, _pair(tmp_path, GOOD)):
        for d in diagnostics_for(json.dumps(SPEC, indent=2), path):
            text = d["message"].lower()
            assert "guard is correct" not in text
            assert "looks good" not in text
            assert "no issues" not in text


def test_an_unbounded_variable_message_is_the_right_way_round():
    """It was backwards on the first attempt, and the flagship example caught it.

    Fewer domain constraints means the obligation must hold for MORE states, so
    the claim is stronger and harder to prove -- not weaker. A diagnostic that
    got this backwards would send a reader to loosen the very bound they need."""
    diags = diagnostics_for(json.dumps(dict(SPEC, domain=[]), indent=2))
    message = " ".join(d["message"] for d in diags if d["code"] == "spec/unbounded")
    assert "stronger, not weaker" in message
    assert "harder to refute" in message


# --------------------------------------------------------------------------- #
# the protocol
# --------------------------------------------------------------------------- #


def _frame(obj) -> bytes:
    body = json.dumps(obj).encode()
    return b"Content-Length: %d\r\n\r\n" % len(body) + body


def _run(messages: list[dict]) -> list[dict]:
    payload = b"".join(_frame(m) for m in messages)
    result = subprocess.run(
        [sys.executable, "-m", "certkit.cli", "lsp"], input=payload, capture_output=True
    )
    assert result.returncode == 0, result.stderr.decode()
    out = result.stdout.decode()
    return [json.loads(part.split("\r\n\r\n", 1)[1]) for part in _split(out)]


def _split(text: str) -> list[str]:
    parts, rest = [], text
    while rest.startswith("Content-Length:"):
        header, body = rest.split("\r\n\r\n", 1)
        length = int(header.split(":", 1)[1])
        parts.append(header + "\r\n\r\n" + body[:length])
        rest = body[length:]
    return parts


def test_initialize_advertises_document_sync():
    replies = _run(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "exit"},
        ]
    )
    assert replies[0]["result"]["capabilities"]["textDocumentSync"]["openClose"] is True
    assert replies[0]["result"]["serverInfo"]["name"] == "certkit-lsp"


def test_opening_a_document_publishes_diagnostics():
    spec = dict(SPEC, domain=[])
    replies = _run(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {
                    "textDocument": {"uri": "file:///tmp/a.spec.json", "text": json.dumps(spec)}
                },
            },
            {"jsonrpc": "2.0", "method": "exit"},
        ]
    )
    published = [r for r in replies if r.get("method") == "textDocument/publishDiagnostics"]
    assert published
    assert published[0]["params"]["uri"] == "file:///tmp/a.spec.json"
    assert published[0]["params"]["diagnostics"]


def test_editing_republishes_from_the_new_text():
    replies = _run(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {
                    "textDocument": {"uri": "file:///tmp/a.spec.json", "text": json.dumps(SPEC)}
                },
            },
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didChange",
                "params": {
                    "textDocument": {"uri": "file:///tmp/a.spec.json"},
                    "contentChanges": [{"text": "{ broken"}],
                },
            },
            {"jsonrpc": "2.0", "method": "exit"},
        ]
    )
    published = [r for r in replies if r.get("method") == "textDocument/publishDiagnostics"]
    assert len(published) == 2
    assert "json" not in {d["code"] for d in published[0]["params"]["diagnostics"]}
    assert published[1]["params"]["diagnostics"][0]["code"] == "json"


def test_an_unknown_request_is_answered_rather_than_left_hanging():
    """An editor that never gets a reply waits forever."""
    replies = _run(
        [
            {"jsonrpc": "2.0", "id": 7, "method": "textDocument/hover", "params": {}},
            {"jsonrpc": "2.0", "method": "exit"},
        ]
    )
    assert replies[0]["id"] == 7
    assert replies[0]["error"]["code"] == -32601


def test_a_notification_for_an_unknown_method_is_ignored_silently():
    replies = _run(
        [
            {"jsonrpc": "2.0", "method": "$/setTrace", "params": {"value": "off"}},
            {"jsonrpc": "2.0", "id": 1, "method": "shutdown"},
            {"jsonrpc": "2.0", "method": "exit"},
        ]
    )
    assert [r.get("id") for r in replies] == [1]


def test_end_of_input_ends_the_server_cleanly():
    replies = _run([{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}])
    assert replies[0]["id"] == 1


@pytest.mark.parametrize(
    "uri,expected_parts",
    [
        ("file:///tmp/a.spec.json", ("tmp", "a.spec.json")),
        ("file:///tmp/with%20space.spec.json", ("tmp", "with space.spec.json")),
        ("http://example.com/a.json", None),
        ("untitled:Untitled-1", None),
    ],
)
def test_uri_handling_refuses_schemes_it_does_not_understand(uri, expected_parts):
    """Compared by path parts, not by string: the separator is the platform's
    business, and a POSIX-only assertion failed the Windows matrix for a
    difference that was not a defect."""
    result = uri_to_path(uri)
    if expected_parts is None:
        assert result is None
    else:
        assert result is not None
        assert result.parts[-len(expected_parts) :] == expected_parts


def test_a_windows_drive_letter_uri_does_not_keep_its_leading_slash():
    """`file:///c%3A/x/a.spec.json` parses to `/c:/x/a.spec.json`, which is not a
    path Windows can open. Found by the CI matrix, not by me."""
    result = uri_to_path("file:///c%3A/work/a.spec.json")
    assert result is not None
    assert not str(result).startswith("/c:")
    assert str(result).lower().startswith("c:")


def test_a_malformed_frame_does_not_kill_the_server():
    payload = (
        b"Content-Length: 9\r\n\r\n{not json"
        + _frame({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        + _frame({"jsonrpc": "2.0", "method": "exit"})
    )
    result = subprocess.run(
        [sys.executable, "-m", "certkit.cli", "lsp"], input=payload, capture_output=True
    )
    assert result.returncode == 0
    assert b'"id": 1' in result.stdout
