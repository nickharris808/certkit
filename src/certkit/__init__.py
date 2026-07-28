"""certkit -- a certificate format for machine-checked program admission, and an
independent checker for it.

The checker imports nothing outside the Python standard library. It contains no
solver, no search, and no floating-point arithmetic. You are meant to read it.

Quickstart::

    from certkit import atom, make_spec, check_certificate

    # "if 19 + payload <= record_len then 3 + payload <= record_len"
    domain = [atom({"payload": -1}), atom({"payload": 1}, -65535)]
    guard  = [atom({"payload": 1, "record_len": -1}, 19)]
    safety = [atom({"payload": 1, "record_len": -1}, 3)]
    spec = make_spec(domain, guard, safety, name="heartbleed")

See ``SPEC.md`` for the on-disk format.
"""

from .atoms import Atom, atom, atom_from_json, atom_to_json, negate
from .cert import (
    ACCEPTED,
    CERT_SCHEMA,
    REFUSED,
    SPEC_SCHEMA,
    UNVERIFIED,
    CheckReport,
    check_certificate,
    fingerprint,
    make_spec,
    reconstruct_obligation,
)
from .farkas import FarkasResult, verify_farkas
from .smtlib import (
    SmtLibError,
    SmtLibUnsupported,
    export_obligation,
    export_spec,
    import_spec,
)
from .sos import SOS_SCHEMA, verify_sos

__version__ = "0.3.0"

__all__ = [
    "ACCEPTED",
    "export_spec",
    "export_obligation",
    "import_spec",
    "SmtLibError",
    "SmtLibUnsupported",
    "REFUSED",
    "UNVERIFIED",
    "Atom",
    "atom",
    "negate",
    "atom_from_json",
    "atom_to_json",
    "verify_farkas",
    "FarkasResult",
    "verify_sos",
    "SOS_SCHEMA",
    "check_certificate",
    "CheckReport",
    "reconstruct_obligation",
    "make_spec",
    "fingerprint",
    "CERT_SCHEMA",
    "SPEC_SCHEMA",
    "__version__",
]
