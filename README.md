# `model-wtf`

The Model W Transformation Facilitator is a CLI tool that facilitates Model W
compliance of a given Git repo.

## Compliance

```
uv run model-wtf compliance check [--strict] [--format text|json|github] [--root PATH]
```

Discovers the repository's compliance _units_ and verifies that something is
declared for each of them.

### Unit discovery

Units are read from `snow.yml` at the repo root: every `images[]` entry that
carries a `compliance: <path>` key is a unit whose compliance folder is
`<context>/<path>`. An image without `compliance` produces a warning (an error
under `--strict`).

```yaml
images:
    - id: api
      context: api
      compliance: compliance # -> api/compliance
    - id: front
      context: .
      compliance: front/compliance
```

Repos not deployed through Snow can use `.model-wtf.yml` instead
(`units: [{id, context, compliance}]`). When both files exist `snow.yml` wins.

The repo-root `compliance/` folder is always loaded as the _shared_ scope
(controller, actors, assumptions, recipients).

### Exit codes

| Code | Meaning                                                         |
| ---- | --------------------------------------------------------------- |
| 0    | Clean                                                           |
| 1    | Open findings / gate failures                                   |
| 2    | Stale attestation                                               |
| 3    | Declaration errors (missing/invalid manifest, `--strict` hits)  |
| 4    | Tool error                                                      |

## Development

```
uv sync
make clean   # format + lint + typecheck
make test
```
