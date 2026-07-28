"""JSON Schema conformance (stress-test item S6).

The schemas exist so other tools can emit certkit formats mechanically. That is
only worth anything if they are *load-bearing*: they must accept everything the
checker accepts, and reject things it rejects. A schema that validates
everything is decoration.

So these tests run in both directions -- every real artefact validates, and a
catalogue of malformed documents does not.

`jsonschema` is a development dependency. certkit itself never imports it, which
is what keeps the zero-dependency property true.
"""

from __future__ import annotations

import json

import pytest

from certkit import atom, make_spec
from certkit.cli import example_path
from certkit.schemas import SCHEMA_DIR, SCHEMA_FILES, load_schema, schema_for

jsonschema = pytest.importorskip("jsonschema")

SPEC_SCHEMA = load_schema("certkit/spec/v1")
CERT_SCHEMA = load_schema("certkit/farkas/v1")


def valid(doc, schema) -> bool:
    try:
        jsonschema.validate(doc, schema)
        return True
    except jsonschema.ValidationError:
        return False


# --------------------------------------------------------------------------- #
# the schemas themselves are well-formed
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", sorted(SCHEMA_FILES))
def test_each_schema_is_itself_valid_json_schema(name):
    jsonschema.Draft202012Validator.check_schema(load_schema(name))


def test_schema_files_are_shipped():
    for filename in SCHEMA_FILES.values():
        assert (SCHEMA_DIR / filename).is_file()


def test_unknown_format_raises_naming_the_known_ones():
    with pytest.raises(KeyError) as exc:
        load_schema("certkit/nope/v9")
    assert "certkit/spec/v1" in str(exc.value)


def test_schema_for_picks_by_the_documents_own_field():
    assert schema_for(make_spec([], [], [atom({"x": 1})])) == SPEC_SCHEMA
    with pytest.raises(KeyError):
        schema_for({"no": "schema field"})
    with pytest.raises(TypeError):
        schema_for("not an object")


# --------------------------------------------------------------------------- #
# everything real validates
# --------------------------------------------------------------------------- #


def test_bundled_examples_validate():
    jsonschema.validate(
        json.loads(example_path("heartbleed.spec.json").read_text(encoding="utf-8")), SPEC_SCHEMA
    )
    for cert_name in ("heartbleed.cert.json", "heartbleed.forged.json"):
        jsonschema.validate(
            json.loads(example_path(cert_name).read_text(encoding="utf-8")), CERT_SCHEMA
        )


def test_generated_specs_validate():
    """Anything make_spec produces must satisfy the published schema."""
    import random

    rng = random.Random(31337)
    for _ in range(200):
        n = rng.randint(1, 4)
        dom = [atom({f"v{i}": rng.randint(-3, 3) or 1}, rng.randint(-9, 9)) for i in range(n)]
        g = [atom({"a": 1, "b": -1}, rng.randint(0, 9))]
        s = [atom({"a": 1, "b": -1}, rng.randint(0, 9)) for _ in range(rng.randint(1, 3))]
        jsonschema.validate(make_spec(dom, g, s, name="gen"), SPEC_SCHEMA)


def test_scaffolded_specs_validate():
    from certkit.scaffold import build_spec

    spec = build_spec(
        ["0 <= payload", "payload <= 65535"],
        ["19 + payload <= record_len"],
        ["3 + payload <= record_len"],
        name="heartbleed",
    )
    jsonschema.validate(spec, SPEC_SCHEMA)


# --------------------------------------------------------------------------- #
# the schemas actually reject things -- otherwise they are decoration
# --------------------------------------------------------------------------- #


BAD_SPECS = [
    {},  # no schema field
    {"schema": "certkit/spec/v1"},  # no safety
    {"schema": "wrong/v1", "safety": [{"coeff": {"x": 1}}]},
    {"schema": "certkit/spec/v1", "safety": []},  # empty conjunction
    {"schema": "certkit/spec/v1", "safety": [{}]},  # atom with no coeff
    {"schema": "certkit/spec/v1", "safety": [{"coeff": {"x": [1, 0]}}]},  # zero denominator
    {"schema": "certkit/spec/v1", "safety": [{"coeff": {"1bad": 1}}]},  # bad identifier
    {"schema": "certkit/spec/v1", "safety": [{"coeff": {"x": "1"}}]},  # string coefficient
    {"schema": "certkit/spec/v1", "safety": [{"coeff": {"x": 1}, "strict": "yes"}]},
    {"schema": "certkit/spec/v1", "safety": [{"coeff": {"x": 1}}], "fingerprint": "short"},
    {"schema": "certkit/spec/v1", "safety": "not-a-list"},
]


@pytest.mark.parametrize("doc", BAD_SPECS)
def test_malformed_specs_are_rejected(doc):
    assert not valid(doc, SPEC_SCHEMA), doc


BAD_CERTS = [
    {},
    {"schema": "certkit/farkas/v1"},  # no obligations
    {"schema": "wrong/v1", "obligations": []},
    {"schema": "certkit/farkas/v1", "obligations": [{}]},  # no multipliers
    {"schema": "certkit/farkas/v1", "obligations": [{"multipliers": {}}]},  # empty
    {"schema": "certkit/farkas/v1", "obligations": [{"multipliers": {"0": -1}}]},  # negative
    {"schema": "certkit/farkas/v1", "obligations": [{"multipliers": {"x": 1}}]},  # bad index
    {"schema": "certkit/farkas/v1", "obligations": [{"multipliers": {"01": 1}}]},  # leading zero
    {"schema": "certkit/farkas/v1", "obligations": [{"multipliers": {"0": [1, 0]}}]},
    {"schema": "certkit/farkas/v1", "obligations": [{"multipliers": {"0": [-1, 2]}}]},
    {"schema": "certkit/farkas/v1", "spec_fingerprint": "nothex", "obligations": []},
]


@pytest.mark.parametrize("doc", BAD_CERTS)
def test_malformed_certificates_are_rejected(doc):
    assert not valid(doc, CERT_SCHEMA), doc


def test_a_mutated_schema_stops_accepting_real_documents():
    """Proves the constraints are doing work, not merely present."""
    spec = json.loads(example_path("heartbleed.spec.json").read_text(encoding="utf-8"))
    assert valid(spec, SPEC_SCHEMA)
    mutated = json.loads(json.dumps(SPEC_SCHEMA))
    mutated["properties"]["schema"]["const"] = "certkit/spec/v2"
    assert not valid(spec, mutated)


def test_rational_string_multipliers_are_accepted():
    """The checker accepts "1/3"; the schema must not be stricter than the checker."""
    doc = {"schema": "certkit/farkas/v1", "obligations": [{"multipliers": {"0": "1/3"}}]}
    assert valid(doc, CERT_SCHEMA)


def test_extra_keys_on_a_certificate_are_allowed():
    """The checker ignores carried atoms; the schema must not forbid them, or it
    would reject documents the checker happily refuses on the merits."""
    doc = {
        "schema": "certkit/farkas/v1",
        "obligations": [{"multipliers": {"0": 1}}],
        "atoms": [{"coeff": {"z": [1, 1]}}],
        "produced_by": "some-solver 1.2",
    }
    assert valid(doc, CERT_SCHEMA)
