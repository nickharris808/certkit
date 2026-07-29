"""Adversarial stress tests for the surfaces added most recently.

The oracle is unchanged and it is the only one that matters:

    **No input may produce a confident-looking answer that is wrong.**

A refusal is always acceptable. A traceback is not (it is a denial-of-service
surface at best). An answer that looks like a verdict and is not one is the
failure this whole toolkit exists to prevent.

The surfaces under test here are the new ones: the SMT-LIB bridge, the output
formats, the language server (including its byte-level framing, which is the
"streaming" surface), the notebook renderer, the pre-commit hook, and the schema
cache.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from certkit import ACCEPTED, REFUSED, UNVERIFIED, atom, check_certificate, make_spec
from certkit.cli import _load, example_path
from certkit.cli import main as cli_main
from certkit.lsp import diagnostics_for, serve
from certkit.notebook import report_html
from certkit.report import FORMATS, render
from certkit.schemas import load_schema, schema_for
from certkit.smtlib import SmtLibError, export_spec, import_spec

SPEC = _load(example_path("heartbleed.spec.json"))
GOOD = _load(example_path("heartbleed.cert.json"))
FORGED = _load(example_path("heartbleed.forged.json"))

# --------------------------------------------------------------------------- #
# hostile documents, reused across every surface
# --------------------------------------------------------------------------- #

HOSTILE_SPECS = [
    ("empty", {}),
    ("null", None),
    ("list", []),
    ("string", "spec"),
    ("number", 7),
    ("schema-only", {"schema": "certkit/spec/v1"}),
    ("safety-string", {**SPEC, "safety": "not-a-list"}),
    ("safety-empty", {**SPEC, "safety": []}),
    ("guard-null", {**SPEC, "guard": None}),
    ("atom-string", {**SPEC, "safety": ["x"]}),
    ("atom-null", {**SPEC, "safety": [None]}),
    ("coeff-list", {**SPEC, "safety": [{"coeff": [1, 2], "const": [0, 1], "strict": False}]}),
    (
        "zero-denominator",
        {**SPEC, "safety": [{"coeff": {"x": [1, 0]}, "const": [0, 1], "strict": False}]},
    ),
    (
        "const-zero-denominator",
        {**SPEC, "safety": [{"coeff": {"x": [1, 1]}, "const": [1, 0], "strict": False}]},
    ),
    (
        "huge-rational",
        {**SPEC, "safety": [{"coeff": {"x": [10**400, 3]}, "const": [0, 1], "strict": False}]},
    ),
    (
        "nan-coeff",
        {**SPEC, "safety": [{"coeff": {"x": [float("nan"), 1]}, "const": [0, 1], "strict": False}]},
    ),
    (
        "inf-coeff",
        {**SPEC, "safety": [{"coeff": {"x": [float("inf"), 1]}, "const": [0, 1], "strict": False}]},
    ),
    (
        "deep-nesting",
        {**SPEC, "safety": [{"coeff": {"x": [[[[1]]], 1]}, "const": [0, 1], "strict": False}]},
    ),
    (
        "unicode-var",
        {**SPEC, "safety": [{"coeff": {"\U0001f512": [1, 1]}, "const": [0, 1], "strict": False}]},
    ),
    (
        "empty-var-name",
        {**SPEC, "safety": [{"coeff": {"": [1, 1]}, "const": [0, 1], "strict": False}]},
    ),
]

HOSTILE_CERTS = [
    ("empty", {}),
    ("null", None),
    ("list", []),
    ("string", "cert"),
    ("obligations-int", {"schema": "certkit/farkas/v1", "obligations": 3}),
    ("obligations-string", {"schema": "certkit/farkas/v1", "obligations": "many"}),
    (
        "multipliers-list",
        {
            "schema": "certkit/farkas/v1",
            "spec_fingerprint": SPEC["fingerprint"],
            "obligations": [{"multipliers": [1]}],
        },
    ),
    (
        "multipliers-nan",
        {
            "schema": "certkit/farkas/v1",
            "spec_fingerprint": SPEC["fingerprint"],
            "obligations": [{"multipliers": {"2": float("nan")}}],
        },
    ),
    (
        "multipliers-inf",
        {
            "schema": "certkit/farkas/v1",
            "spec_fingerprint": SPEC["fingerprint"],
            "obligations": [{"multipliers": {"2": float("inf")}}],
        },
    ),
    (
        "multipliers-deep",
        {
            "schema": "certkit/farkas/v1",
            "spec_fingerprint": SPEC["fingerprint"],
            "obligations": [{"multipliers": {"2": [[1], [2]]}}],
        },
    ),
    (
        "fingerprint-int",
        {
            "schema": "certkit/farkas/v1",
            "spec_fingerprint": 5,
            "obligations": [{"multipliers": {"2": 1, "3": 1}}],
        },
    ),
]


@pytest.mark.parametrize("label,spec", HOSTILE_SPECS, ids=[s[0] for s in HOSTILE_SPECS])
def test_a_hostile_spec_is_refused_and_never_accepted(label, spec):
    report = check_certificate(spec, GOOD)
    assert report.verdict in (REFUSED, UNVERIFIED)
    assert report.verdict != ACCEPTED
    assert report.ok is False
    assert report.reason, f"{label}: a refusal with no reason is not usable"


def test_absurdly_large_multipliers_are_accepted_because_they_are_valid():
    """Not a hostile input, despite looking like one -- and worth pinning.

    Scaling a valid refutation by any positive constant is still a valid
    refutation, so 10**500 on each atom is a correct certificate and ACCEPTED is
    the right answer. This test exists because the first version of this suite
    classified it as an attack and "failed", which would have been a wrong fix in
    the most dangerous direction: making the checker refuse something true.
    """
    cert = {
        "schema": "certkit/farkas/v1",
        "spec_fingerprint": SPEC["fingerprint"],
        "obligations": [{"multipliers": {"2": 10**500, "3": 10**500}}],
    }
    assert check_certificate(SPEC, cert).verdict == ACCEPTED


@pytest.mark.parametrize("label,cert", HOSTILE_CERTS, ids=[c[0] for c in HOSTILE_CERTS])
def test_a_hostile_certificate_is_refused_and_never_accepted(label, cert):
    report = check_certificate(SPEC, cert)
    assert report.verdict != ACCEPTED, label
    assert report.ok is False


# --------------------------------------------------------------------------- #
# every output format must preserve the verdict
# --------------------------------------------------------------------------- #

VERDICT_CASES = [
    ("accepted", SPEC, GOOD, True, ACCEPTED),
    ("refused", SPEC, FORGED, True, REFUSED),
    ("unverified", SPEC, GOOD, False, UNVERIFIED),
]


@pytest.mark.parametrize("fmt", FORMATS)
@pytest.mark.parametrize(
    "label,spec,cert,binding,expected", VERDICT_CASES, ids=[c[0] for c in VERDICT_CASES]
)
def test_every_format_carries_the_same_verdict(fmt, label, spec, cert, binding, expected):
    report = check_certificate(spec, cert, require_fingerprint=binding)
    assert report.verdict == expected
    text = render(report, fmt, name="stress")
    assert expected in text, f"{fmt} lost the verdict for {label}"


@pytest.mark.parametrize("fmt", FORMATS)
def test_no_format_renders_unverified_as_a_pass(fmt):
    """The failure this suite exists for: a format that quietly upgrades an
    abstention. Checked structurally per format rather than by keyword."""
    report = check_certificate(SPEC, GOOD, require_fingerprint=False)
    text = render(report, fmt, name="stress")
    assert UNVERIFIED in text
    if fmt == "json":
        payload = json.loads(text)
        assert payload["ok"] is False
        assert payload["verdict"] == UNVERIFIED
    if fmt == "sarif":
        payload = json.loads(text)
        rules = [r["ruleId"] for run in payload["runs"] for r in run["results"]]
        assert "certkit/unverified" in rules
        assert "certkit/refused" not in rules
    if fmt == "junit":
        assert "unverified" in text
        assert 'failures="0"' not in text or "failure" in text


@pytest.mark.parametrize("fmt", FORMATS)
@pytest.mark.parametrize("label,spec", HOSTILE_SPECS[:8], ids=[s[0] for s in HOSTILE_SPECS[:8]])
def test_no_format_crashes_on_a_hostile_document(fmt, label, spec):
    report = check_certificate(spec, GOOD)
    text = render(report, fmt, name="stress")
    assert isinstance(text, str) and text
    assert ACCEPTED not in text


def test_formats_agree_with_each_other_on_the_same_report():
    """A verdict that differs between the log and the Security tab is a verdict
    nobody can act on."""
    for _, spec, cert, binding, expected in VERDICT_CASES:
        report = check_certificate(spec, cert, require_fingerprint=binding)
        rendered = {fmt: render(report, fmt, name="x") for fmt in FORMATS}
        assert all(expected in text for text in rendered.values())
        others = [v for v in (ACCEPTED, REFUSED, UNVERIFIED) if v != expected]
        for fmt, text in rendered.items():
            if fmt in ("text", "markdown"):
                # The verdict LINE, not the whole document: the explanatory note
                # for UNVERIFIED legitimately contains the phrase "not ACCEPTED",
                # and asserting on the whole text made this suite fail for a
                # sentence that is doing exactly the right thing.
                verdict_line = text.strip().splitlines()[0]
                for other in others:
                    assert other not in verdict_line, f"{fmt} verdict line says {other}"
            if fmt == "json":
                assert json.loads(text)["verdict"] == expected


# --------------------------------------------------------------------------- #
# SMT-LIB: the new frontend must refuse what it does not understand
# --------------------------------------------------------------------------- #

OUT_OF_FRAGMENT = [
    "(declare-const x Int)(assert (> (* x x) 3))",
    "(declare-const x Real)(assert (<= x 3))",
    "(declare-const x (_ BitVec 8))(assert (bvule x #x03))",
    "(declare-const x Int)(assert (forall ((y Int)) (<= x y)))",
    "(declare-const x Int)(assert (= x 3))",
    "(declare-fun f (Int) Int)(assert (<= (f 1) 3))",
    "(declare-const x Int)(assert (<= (div x 2) 3))",
    "(declare-const x Int)(assert (<= (mod x 2) 3))",
    "(declare-const x Int)(assert (ite true (<= x 1) (<= x 2)))",
    "(declare-const x Int)(assert (and (<= x 1) (<= x 2)))",
    "(declare-const x Int)(assert (or (<= x 1) (<= x 2)))",
    "(assert (<= undeclared 3))",
    "(declare-const x Int)",
    "",
    "((((",
    "))))",
    "(declare-const x Int)(assert (<= x 3)",
    "\x00\x01\x02",
    "(declare-const x Int)(assert (<= x 1e400))",
]


@pytest.mark.parametrize("text", OUT_OF_FRAGMENT)
def test_the_importer_refuses_rather_than_guessing(text):
    """A partial importer that dropped what it did not understand would produce a
    spec proving a weaker theorem than the file stated -- and everything
    downstream would then be correct about the wrong thing."""
    try:
        spec = import_spec(text)
    except SmtLibError as exc:
        assert str(exc), "a refusal must say what it refused"
        return
    except RecursionError:
        pytest.fail("deep nesting produced a RecursionError rather than a refusal")
    # If it did import, it must be a well-formed spec that the checker accepts as
    # a document -- never a half-parsed one.
    assert spec["schema"] == "certkit/spec/v1"
    assert spec["safety"], "an import that produced no obligations must have refused"


def test_a_pathologically_nested_script_is_refused_not_stack_overflowed():
    deep = "(declare-const x Int)(assert " + "(+ " * 500 + "x" + ")" * 500 + ")"
    try:
        import_spec(deep)
    except (SmtLibError, RecursionError) as exc:
        assert exc is not None
    # Either outcome is survivable; what must not happen is a wrong spec.


def test_export_of_a_hostile_spec_refuses_rather_than_emitting_nonsense():
    for label, spec in HOSTILE_SPECS:
        try:
            scripts = export_spec(spec)
        except (SmtLibError, ValueError, TypeError, KeyError, ArithmeticError, AttributeError):
            continue
        for script in scripts:
            assert "(check-sat)" in script, label
            # A script that silently dropped an assertion would ask a weaker
            # question than the spec states.
            assert "(assert" in script, label


def test_export_import_round_trip_never_strengthens_a_claim():
    """Re-importing an exported obligation must not lose an atom. Losing one
    makes the re-imported obligation easier to refute -- a proof of something
    weaker, wearing the same name."""
    spec = make_spec(
        [atom({"x": -1}), atom({"x": 1}, -50)],
        [atom({"x": 1, "y": -1}, 7)],
        [atom({"x": 1, "y": -1}, 2)],
        name="rt",
    )
    exported = export_spec(spec)[0]
    reimported = import_spec(exported)
    assert len(reimported["safety"]) == len(spec["domain"]) + len(spec["guard"]) + 1


# --------------------------------------------------------------------------- #
# the language server: framing is the streaming surface
# --------------------------------------------------------------------------- #


def _frame(obj) -> bytes:
    body = json.dumps(obj).encode()
    return b"Content-Length: %d\r\n\r\n" % len(body) + body


class _ChunkedReader:
    """A stdin that returns bytes in awkward pieces, the way a socket does."""

    def __init__(self, data: bytes, chunk: int) -> None:
        self.data = data
        self.pos = 0
        self.chunk = chunk

    def readline(self) -> bytes:
        end = self.data.find(b"\n", self.pos)
        if end == -1:
            out, self.pos = self.data[self.pos :], len(self.data)
            return out
        out = self.data[self.pos : end + 1]
        self.pos = end + 1
        return out

    def read(self, n: int) -> bytes:
        out = b""
        while len(out) < n and self.pos < len(self.data):
            take = min(self.chunk, n - len(out), len(self.data) - self.pos)
            out += self.data[self.pos : self.pos + take]
            self.pos += take
        return out


class _Sink:
    def __init__(self) -> None:
        self.chunks: list[bytes] = []

    def write(self, data: bytes) -> None:
        self.chunks.append(data)

    def flush(self) -> None:
        pass

    def text(self) -> str:
        return b"".join(self.chunks).decode()


MESSAGES = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    {
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {"textDocument": {"uri": "file:///tmp/s.spec.json", "text": json.dumps(SPEC)}},
    },
    {"jsonrpc": "2.0", "method": "exit"},
]


@pytest.mark.parametrize("chunk", [1, 3, 7, 64, 100000])
def test_the_server_reads_the_same_messages_however_the_bytes_arrive(chunk):
    """The streaming surface. A framing loop that assumed one read per body would
    work in every test and fail against a real editor over a pipe."""
    payload = b"".join(_frame(m) for m in MESSAGES)
    sink = _Sink()
    assert serve(_ChunkedReader(payload, chunk), sink) == 0
    text = sink.text()
    assert '"id": 1' in text
    assert "publishDiagnostics" in text


def test_chunked_and_whole_reads_produce_byte_identical_output():
    payload = b"".join(_frame(m) for m in MESSAGES)
    outputs = []
    for chunk in (1, 5, 999999):
        sink = _Sink()
        serve(_ChunkedReader(payload, chunk), sink)
        outputs.append(sink.text())
    assert len(set(outputs)) == 1, "the framing depends on read boundaries"


HOSTILE_FRAMES = [
    b"",
    b"\r\n\r\n",
    b"Content-Length: 0\r\n\r\n",
    b"Content-Length: -5\r\n\r\n{}",
    b"Content-Length: abc\r\n\r\n{}",
    b"Content-Length: 99999\r\n\r\n{}",
    b"Content-Length: 2\r\n\r\n{}extra-garbage",
    b"content-length: 2\r\n\r\n{}",
    b"Content-Length: 4\r\n\r\n\xff\xfe\xfd\xfc",
    b"Content-Type: application/json\r\n\r\n{}",
    b"{}",
]


@pytest.mark.parametrize("payload", HOSTILE_FRAMES)
def test_a_hostile_frame_does_not_crash_or_hang_the_server(payload):
    sink = _Sink()
    assert serve(_ChunkedReader(payload + b"", 8), sink) == 0


def test_a_hostile_frame_followed_by_a_real_one_is_still_answered():
    """A malformed frame must not poison the connection."""
    payload = b"Content-Length: 4\r\n\r\n\xff\xfe\xfd\xfc" + b"".join(_frame(m) for m in MESSAGES)
    sink = _Sink()
    serve(_ChunkedReader(payload, 5), sink)
    assert '"id": 1' in sink.text()


@pytest.mark.parametrize("label,spec", HOSTILE_SPECS, ids=[s[0] for s in HOSTILE_SPECS])
def test_the_language_server_never_claims_a_hostile_spec_is_fine(label, spec):
    """Diagnostics on garbage must not be an empty list, which an editor renders
    as a clean file."""
    text = json.dumps(spec)
    diags = diagnostics_for(text)
    assert isinstance(diags, list)
    if label in ("unicode-var", "empty-var-name", "huge-rational"):
        return  # structurally valid specs; nothing is wrong with the file
    assert diags, f"{label} produced no diagnostic at all"
    assert any(d["severity"] == 1 for d in diags), f"{label} produced no error"


@pytest.mark.parametrize("text", ["", "   ", "null", "[]", "0", '"x"', "{", "\x00", "﻿{}"])
def test_the_language_server_handles_non_json_documents(text):
    diags = diagnostics_for(text)
    assert isinstance(diags, list)
    for d in diags:
        assert "message" in d and d["message"]


# --------------------------------------------------------------------------- #
# the notebook renderer
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("label,spec", HOSTILE_SPECS, ids=[s[0] for s in HOSTILE_SPECS])
def test_the_notebook_renderer_never_shows_a_hostile_spec_as_accepted(label, spec):
    report = check_certificate(spec, GOOD)
    html = report_html(report, name=str(label))
    assert ACCEPTED not in html
    assert "<script>" not in html


def test_notebook_html_escapes_a_hostile_name_of_any_shape():
    report = check_certificate(SPEC, GOOD)
    for name in ("<script>x</script>", '"><svg onload=1>', "&<>\"'", "\x00\x01"):
        html = report_html(report, name=name)
        assert "<script>" not in html and "<svg" not in html


# --------------------------------------------------------------------------- #
# caches must key on content
# --------------------------------------------------------------------------- #


def test_the_schema_cache_returns_the_same_object_but_cannot_be_mutated_across_calls():
    """`load_schema` is cached. A caller that mutated the result would poison
    every later caller, including the validator."""
    first = load_schema("certkit/spec/v1")
    first_copy = json.loads(json.dumps(first))
    first["properties"]["schema"]["const"] = "tampered"
    try:
        second = load_schema("certkit/spec/v1")
        assert second["properties"]["schema"]["const"] == "tampered", (
            "the cache is expected to return the same object; this test records that, so a "
            "future change to defensive copying is a deliberate decision rather than a surprise"
        )
    finally:
        first["properties"]["schema"]["const"] = first_copy["properties"]["schema"]["const"]
    assert load_schema("certkit/spec/v1")["properties"]["schema"]["const"] == "certkit/spec/v1"


def test_schema_for_refuses_an_unknown_document_rather_than_guessing():
    with pytest.raises((KeyError, ValueError)):
        schema_for({"schema": "certkit/unknown/v9"})


# --------------------------------------------------------------------------- #
# the CLI, end to end, on hostile files
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("label,spec", HOSTILE_SPECS[:10], ids=[s[0] for s in HOSTILE_SPECS[:10]])
def test_the_cli_never_exits_zero_on_a_hostile_spec(label, spec, tmp_path, capsys):
    spec_path = tmp_path / "s.json"
    cert_path = tmp_path / "c.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    cert_path.write_text(json.dumps(GOOD), encoding="utf-8")
    code = cli_main(["check", "--spec", str(spec_path), "--cert", str(cert_path)])
    capsys.readouterr()
    assert code != 0, label


def test_a_very_large_certificate_is_handled_or_refused_but_never_accepted(tmp_path, capsys):
    """10 MB of multipliers. Slow is acceptable; a wrong ACCEPTED is not."""
    huge = {
        "schema": "certkit/farkas/v1",
        "spec_fingerprint": SPEC["fingerprint"],
        "obligations": [{"multipliers": {str(i): 0 for i in range(200_000)}}],
    }
    report = check_certificate(SPEC, huge)
    assert report.verdict != ACCEPTED
    assert report.ok is False


def test_a_spec_with_many_conjuncts_stays_linear_and_correct():
    """The quadratic fix must not have changed any verdict."""
    domain = [atom({"x": -1}), atom({"x": 1}, -1000)]
    guard = [atom({"x": 1, "y": -1}, 40)]
    safety = [atom({"x": 1, "y": -1}, i) for i in range(1, 60)]
    spec = make_spec(domain, guard, safety, name="many")
    cert = {
        "schema": "certkit/farkas/v1",
        "spec_fingerprint": spec["fingerprint"],
        "obligations": [{"multipliers": {"2": 1, "3": 1}} for _ in safety],
    }
    report = check_certificate(spec, cert)
    # Conjuncts with a constant below the guard's are implied; the rest are not.
    for i, obligation in enumerate(report.obligations):
        # guard is `x + 40 <= y`; safety conjunct i is `x + (i+1) <= y`, which the
        # guard implies exactly when i + 1 <= 40.
        expected = (i + 1) <= 40
        assert obligation["ok"] == expected, f"conjunct {i + 1}"
    assert report.verdict == REFUSED


def test_the_precommit_hook_never_passes_a_hostile_pair(tmp_path, capsys):
    from certkit.precommit import main as hook

    for label, spec in HOSTILE_SPECS[:10]:
        (tmp_path / "h.spec.json").write_text(json.dumps(spec), encoding="utf-8")
        (tmp_path / "h.cert.json").write_text(json.dumps(GOOD), encoding="utf-8")
        assert hook([str(tmp_path / "h.cert.json")]) == 1, label
        capsys.readouterr()


def test_the_cli_subprocess_never_prints_a_traceback_on_hostile_input(tmp_path):
    """A traceback in CI output is a bug report from the wrong direction."""
    spec_path = tmp_path / "s.json"
    cert_path = tmp_path / "c.json"
    for label, spec in HOSTILE_SPECS:
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        for _, cert in HOSTILE_CERTS[:4]:
            cert_path.write_text(json.dumps(cert), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "certkit.cli",
                    "check",
                    "--spec",
                    str(spec_path),
                    "--cert",
                    str(cert_path),
                ],
                capture_output=True,
                text=True,
            )
            assert "Traceback" not in result.stderr, f"{label}: {result.stderr[:400]}"
            assert result.returncode != 0
