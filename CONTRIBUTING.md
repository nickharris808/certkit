# Contributing to certkit

Thanks for looking. This package has an unusual constraint that shapes every contribution.

## The one hard rule: the trusted core stays small and dependency-free

`farkas.py`, `sos.py`, and `atoms.py` are the trusted base. They must:

- import **nothing** outside the Python standard library;
- contain **no floating-point arithmetic** (a rounding error in a proof checker is a soundness bug,
  not a precision nuisance);
- contain **no search, no solver, no LP** — finding a certificate is the producer's job;
- **reject** malformed input rather than raise. These functions consume attacker-controlled data.

A pull request that adds a dependency to the trusted core will be declined regardless of how useful
the dependency is. Convenience belongs in a layer above.

## Tests

Every change needs a test, and negative tests are worth more than positive ones here. If you add a
check, add the input that the check is supposed to catch.

```bash
pip install -e ".[dev]"
pytest
```

## Soundness bugs

If you find a certificate that `certkit` accepts but which does not actually establish its claimed
property, that is the most valuable bug report we can receive. Please open an issue with the spec
and certificate JSON. We would much rather hear it than not.

## Style

Match the surrounding code: type hints on public functions, docstrings that explain *why* rather
than restate the signature, and comments where a reader might reasonably wonder "is this safe?"

## License

Contributions are accepted under Apache-2.0, the license of the project.
