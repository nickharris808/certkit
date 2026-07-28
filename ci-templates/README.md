# CI templates

`certkit-action` covers GitHub Actions. These cover the rest.

| File | For |
|---|---|
| `gitlab-ci.yml` | GitLab CI, with JUnit reports rendered natively |
| `circleci.yml` | CircleCI, with `store_test_results` |
| `../.pre-commit-hooks.yaml` | [pre-commit](https://pre-commit.com), locally and in CI |

All three treat **exit 3 (`UNVERIFIED`) as a failure**. That is deliberate and it is the one thing
to preserve if you rewrite them: exit 3 means the tool declined to certify, and a gate that let it
through would be merging on the strength of a check that explicitly did not happen.

They also fail when a `*.cert.json` has no `*.spec.json` beside it, rather than skipping it. A gate
that silently skips what it cannot check reports "all certificates verified" while verifying none.

## pre-commit

```yaml
repos:
  - repo: https://github.com/nickharris808/certkit
    rev: main
    hooks:
      - id: certkit
```

Then `pre-commit install`. Every staged `*.cert.json` is checked against the spec beside it.
