# `model-wtf`

The Model W Transformation Facilitator is a CLI tool that facilitates Model W
compliance of a given Git repo.

It maintains a compliance-oriented model of the application — its data,
components and flows — declared in YAML under `compliance/` folders next to
the code. That model feeds static analysis and code review, and derived
documents such as the GDPR Art. 30 registry or the pytm threat model.

## Compliance

```
uv run model-wtf compliance init  [--name X] [--controller-name X --controller-country CC]
                                  [--processor-name X --processor-country CC | --no-processor]
uv run model-wtf compliance check [--strict] [--format text|json|github] [--root PATH]
```

`init` scaffolds the repo-root `compliance/` folder (`app.yaml`, one
`parties/<id>.yaml` per organisation, a README), adds a `compliance:` block to
every image of `snow.yml` (guessing the discovery engine from the code) and
creates the per-unit folders. It never
overwrites anything; re-run it to add what is missing. Values left for a human
are written as the YAML tag `!todo`. The processor defaults to
`default_processor: {name, country, address, email}` from
`~/.config/model-wtf/config.yml`.

`check` discovers the units, validates every declaration file against its
schema (pydantic; unknown keys are errors) and lists the `!todo` values.

### Files

- `compliance/app.yaml` — `name`, `description`, `controller` (party id, the
  client) and optional `processor` (party id, the agency).
- `compliance/parties/<id>.yaml` — `name`, `country` (ISO alpha-2),
  `address`, `email`; optional `phone`, `website`, `registration`, `dpo` and
  `representative` contact blocks. A party is role-less: controller, processor
  or recipient is decided per processing activity.

### Unit discovery

Units are read from `snow.yml` at the repo root: every `images[]` entry that
carries a `compliance:` block is a unit. `discover` names the discovery engine
for that codebase (`django`, `sveltekit`, `none`); the compliance folder is
`compliance/` next to the image's Dockerfile unless `dir` (relative to the
build context) says otherwise. An image without `compliance` produces a
warning (an error under `--strict`).

```yaml
images:
    - id: api
      context: api                 # Dockerfile at api/Dockerfile
      compliance:
          discover: django         # -> api/compliance
    - id: front
      context: .
      dockerfile: front/Dockerfile
      compliance:
          discover: sveltekit      # -> front/compliance
    - id: docs
      context: .
      compliance:
          discover: none
          dir: docs/compliance     # -> docs/compliance
```

Repos not deployed through Snow can use `.model-wtf.yml` instead
(`units: [{id, context, dockerfile, compliance}]`). When both files exist
`snow.yml` wins.

The repo-root `compliance/` folder is always loaded as the _shared_ scope
(controller, actors, assumptions, recipients).

### Exit codes

| Code | Meaning                                                         |
| ---- | --------------------------------------------------------------- |
| 0    | Clean                                                           |
| 1    | Todo findings / `!todo` values still to fill                    |
| 2    | Stale attestation                                               |
| 3    | Declaration errors (schema, missing files, dangling party ids)  |
| 4    | Tool error                                                      |

## Development

```
uv sync
make clean   # format + lint + typecheck
make test
```
