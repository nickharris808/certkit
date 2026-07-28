"""Tests for `certkit init` -- writing relations instead of JSON atoms.

The load-bearing test is :func:`test_scaffold_reproduces_the_bundled_example`.
The bundled Heartbleed spec was written by hand in canonical form; if parsing
the same relations in plain text produces a byte-identical spec, then the parser
agrees with the format on a real example rather than on a toy one.

The rest of the file is about the parser refusing what it does not understand.
A spec silently parsed into the wrong relation is worse than a rejected one,
because every downstream proof would then be about the wrong thing.
"""

from __future__ import annotations

import json

import pytest

from certkit import atom, check_certificate
from certkit.cli import example_path
from certkit.cli import main as cli_main
from certkit.scaffold import RelationSyntaxError, build_spec, parse_relation


def test_scaffold_reproduces_the_bundled_example():
    """Plain-text relations must produce exactly the hand-written spec."""
    scaffolded = build_spec(
        ["0 <= payload", "payload <= 65535"],
        ["19 + payload <= record_len"],
        ["3 + payload <= record_len"],
        name="heartbleed",
    )
    bundled = json.loads(example_path("heartbleed.spec.json").read_text(encoding="utf-8"))
    assert scaffolded == bundled
    assert scaffolded["fingerprint"] == bundled["fingerprint"]


def test_scaffolded_spec_verifies_with_the_bundled_certificate():
    scaffolded = build_spec(
        ["0 <= payload", "payload <= 65535"],
        ["19 + payload <= record_len"],
        ["3 + payload <= record_len"],
        name="heartbleed",
    )
    cert = json.loads(example_path("heartbleed.cert.json").read_text(encoding="utf-8"))
    assert check_certificate(scaffolded, cert).ok is True


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "text,expected",
    [
        ("0 <= payload", atom({"payload": -1})),
        ("payload <= 65535", atom({"payload": 1}, -65535)),
        ("19 + payload <= record_len", atom({"payload": 1, "record_len": -1}, 19)),
        ("record_len >= payload + 19", atom({"payload": 1, "record_len": -1}, 19)),
        ("2*offset + len < size", atom({"offset": 2, "len": 1, "size": -1}, 0, strict=True)),
        ("n > 0", atom({"n": -1}, 0, strict=True)),
        ("-x <= 5", atom({"x": -1}, -5)),
        ("a - b <= 0", atom({"a": 1, "b": -1})),
    ],
)
def test_relations_parse_to_the_expected_atom(text, expected):
    got = parse_relation(text)
    assert got.coeff == expected.coeff, text
    assert got.const == expected.const, text
    assert got.strict == expected.strict, text


def test_ge_is_flipped_not_dropped():
    """`a >= b` must become `b - a <= 0`, not `a - b <= 0`."""
    assert parse_relation("x >= 3").coeff == parse_relation("3 <= x").coeff
    assert parse_relation("x >= 3").const == parse_relation("3 <= x").const


def test_strictness_survives_the_flip():
    assert parse_relation("x > 3").strict is True
    assert parse_relation("x >= 3").strict is False


# --------------------------------------------------------------------------- #
# refusals -- a guess here would poison everything downstream
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "payload",  # no comparison
        "19 + payload",  # no comparison
        "3 <= 5",  # no variables: a constant claim, not a relation
        "x <= y ?? z",  # junk
        "x <= 3;DROP TABLE",  # junk
        "2 * <= 3",  # coefficient with no variable
    ],
)
def test_unparseable_relations_are_refused(bad):
    with pytest.raises(RelationSyntaxError):
        parse_relation(bad)


def test_equality_is_refused_rather_than_split():
    """`a == b` is two atoms; silently choosing one would change the spec."""
    with pytest.raises(RelationSyntaxError) as exc:
        parse_relation("a == b")
    assert "two inequalities" in str(exc.value)


def test_error_names_the_offending_relation():
    with pytest.raises(RelationSyntaxError) as exc:
        build_spec([], ["this is not a relation"], ["x <= 1"])
    assert "--guard" in str(exc.value)
    assert "this is not a relation" in str(exc.value)


def test_spec_without_safety_is_refused():
    with pytest.raises(RelationSyntaxError) as exc:
        build_spec(["0 <= x"], ["x <= 5"], [])
    assert "at least one --safety" in str(exc.value)


# --------------------------------------------------------------------------- #
# the CLI surface
# --------------------------------------------------------------------------- #


def test_cli_init_writes_a_checkable_spec(tmp_path, capsys):
    out = tmp_path / "my.spec.json"
    code = cli_main(
        [
            "init",
            "--domain",
            "0 <= payload",
            "--domain",
            "payload <= 65535",
            "--guard",
            "19 + payload <= record_len",
            "--safety",
            "3 + payload <= record_len",
            "--name",
            "heartbleed",
            "-o",
            str(out),
        ]
    )
    assert code == 0
    assert "Next:" in capsys.readouterr().out  # tells you what to do with it
    spec = json.loads(out.read_text(encoding="utf-8"))
    cert = json.loads(example_path("heartbleed.cert.json").read_text(encoding="utf-8"))
    assert check_certificate(spec, cert).ok is True


def test_cli_init_reports_a_syntax_error_usefully(capsys):
    """An error must name the input, the field, and a form that would work."""
    code = cli_main(["init", "--safety", "not a relation"])
    assert code == 2
    err = capsys.readouterr().err
    assert "not a relation" in err  # the offending text
    assert "--safety" in err  # which field it came from
    assert "19 + payload <= record_len" in err  # what a good one looks like
