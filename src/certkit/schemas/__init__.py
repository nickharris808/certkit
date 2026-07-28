"""Machine-readable JSON Schemas for the certkit formats.

`SPEC.md` documents the format in prose, which is good for a reader and useless
for a tool. Anything that wants to *emit* certkit specs -- a solver front end, a
CI plugin, another language's implementation -- needs a definition it can check
itself against. These are it.

The schemas describe **shape**, and that is all. Passing validation means the
JSON is well-formed certkit; it says nothing about whether the relations are
true, whether the multipliers refute anything, or whether the spec describes your
program. `check_certificate` decides those. A schema is not a verdict.

Loading a schema needs no third-party package -- these are data files read with
:mod:`json`, so certkit keeps its zero-dependency property. Validating *against*
them needs a JSON Schema implementation, which is a development dependency here
and never imported at runtime.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

__all__ = ["SCHEMA_DIR", "SCHEMA_FILES", "load_schema", "schema_for"]

SCHEMA_DIR = Path(__file__).resolve().parent

#: Format identifier -> schema filename.
SCHEMA_FILES: dict[str, str] = {
    "certkit/spec/v1": "certkit-spec-v1.schema.json",
    "certkit/farkas/v1": "certkit-farkas-v1.schema.json",
}


@cache  # schemas are immutable data; loading one twice is pure waste
def load_schema(name: str) -> dict[str, Any]:
    """Load a schema by format identifier, e.g. ``"certkit/spec/v1"``.

    Raises :class:`KeyError` naming the known identifiers rather than returning
    something empty, because a caller that silently validated against ``{}``
    would believe everything.
    """
    try:
        filename = SCHEMA_FILES[name]
    except KeyError:
        known = ", ".join(sorted(SCHEMA_FILES))
        raise KeyError(f"no schema for {name!r}; known formats are: {known}") from None
    return json.loads((SCHEMA_DIR / filename).read_text(encoding="utf-8"))


def schema_for(document: Any) -> dict[str, Any]:
    """Pick the schema matching a document's own ``schema`` field."""
    if not isinstance(document, dict):
        raise TypeError(f"expected a JSON object, got {type(document).__name__}")
    declared = document.get("schema")
    if not isinstance(declared, str):
        raise KeyError("document has no 'schema' field, so its format is unknown")
    return load_schema(declared)
