"""CLI tests, including the packaging invariant that broke once already.

The bundled examples must be importable from the *installed* package, not just
present in the source tree. An earlier build shipped wheels with no examples at
all, which silently broke the documented quickstart for every pip user while the
whole test suite stayed green.
"""

import json

from certkit.cli import example_path, main


def test_bundled_examples_exist_in_the_installed_package():
    """Guards against shipping a wheel whose examples were left behind."""
    for name in ("heartbleed.spec.json", "heartbleed.cert.json", "heartbleed.forged.json"):
        path = example_path(name)
        assert path.is_file(), f"missing bundled example: {name}"
        json.loads(path.read_text(encoding="utf-8"))


def test_demo_runs_with_no_files_and_succeeds(capsys):
    assert main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "valid certificate  -> ACCEPTED" in out
    assert "forged certificate -> REFUSED" in out


def test_check_accepts_the_bundled_valid_certificate(capsys):
    code = main(
        [
            "check",
            "--spec",
            str(example_path("heartbleed.spec.json")),
            "--cert",
            str(example_path("heartbleed.cert.json")),
        ]
    )
    assert code == 0
    assert "ACCEPTED" in capsys.readouterr().out


def test_check_refuses_the_bundled_forgery(capsys):
    code = main(
        [
            "check",
            "--spec",
            str(example_path("heartbleed.spec.json")),
            "--cert",
            str(example_path("heartbleed.forged.json")),
        ]
    )
    assert code == 1
    assert "REFUSED" in capsys.readouterr().out


def test_json_output_is_machine_readable(capsys):
    main(
        [
            "check",
            "--json",
            "--spec",
            str(example_path("heartbleed.spec.json")),
            "--cert",
            str(example_path("heartbleed.cert.json")),
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["obligations"][0]["ok"] is True


def test_missing_file_is_usage_error_not_a_pass():
    assert main(["check", "--spec", "nope.json", "--cert", "nope.json"]) == 2
    assert main(["sos", "--cert", "nope.json"]) == 2


def test_sos_subcommand_end_to_end(tmp_path, capsys):
    cert = tmp_path / "sos.json"
    cert.write_text(
        json.dumps(
            {
                "schema": "certkit/sos/v1",
                "scale": 1,
                "target": {"2,0": [1, 1]},
                "squares": [{"1,0": [1, 1]}],
            }
        )
    )
    assert main(["sos", "--cert", str(cert)]) == 0
    assert "ACCEPTED" in capsys.readouterr().out


def test_sos_subcommand_refuses_a_bad_identity(tmp_path, capsys):
    cert = tmp_path / "sos.json"
    cert.write_text(
        json.dumps(
            {
                "schema": "certkit/sos/v1",
                "scale": 1,
                "target": {"2,0": [2, 1]},  # 2x^2 != (x)^2
                "squares": [{"1,0": [1, 1]}],
            }
        )
    )
    assert main(["sos", "--cert", str(cert)]) == 1
    assert "REFUSED" in capsys.readouterr().out
