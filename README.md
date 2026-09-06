# `model-wtf`

The Model W Transformation Facilitator is a CLI tool that facilitates Model W
compliance of a given Git repo.

## Compliance

```
uv run model-wtf compliance init  [--name X] [--controller-name X --controller-country CC]
                                  [--processor-name X --processor-country CC | --no-processor]
uv run model-wtf compliance check [--strict] [--format text|json|github] [--root PATH]
```

`init` scaffolds the repo-root `compliance/` folder (`app.yaml`, one
`parties/<id>.yaml` per organisation, a README), adds `compliance: compliance`
to every image of `snow.yml` and creates the per-unit folders. It never
overwrites anything; re-run it to add what is missing. Values left for a human
are written as the YAML tag `!open`. The processor defaults to
`default_processor: {name, country, address, email}` from
`~/.config/model-wtf/config.yml`.

`check` discovers the units, validates every declaration file against its
schema (pydantic; unknown keys are errors) and lists the `!open` values.

### Files

- `compliance/app.yaml` — `name`, `description`, `controller` (party id, the
  client) and optional `processor` (party id, the agency).
- `compliance/parties/<id>.yaml` — `name`, `country` (ISO alpha-2),
  `address`, `email`; optional `phone`, `website`, `registration`, `dpo` and
  `representative` contact blocks. A party is role-less: controller, processor
  or recipient is decided per processing activity.

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
| 1    | Open findings / `!open` values still to fill                    |
| 2    | Stale attestation                                               |
| 3    | Declaration errors (schema, missing files, dangling party ids)  |
| 4    | Tool error                                                      |

## Development

```
uv sync
make clean   # format + lint + typecheck
make test
```
