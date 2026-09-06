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
every image of `snow.yml` (guessing the discovery backend from the code) and
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
carries a `compliance:` block is a unit. `discover` names the discovery backend
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

### Data inventory

```
uv run model-wtf compliance data list  [--unit ID] [--format table|json]
uv run model-wtf compliance data rules
uv run model-wtf compliance data override <unit>:<app.Model.field> [--pii|--no-pii] [--sensitivity L] [--category C] [--reason TEXT]
```

Every Django model field of every `discover: django` unit is inventoried
live — model-wtf detects the unit's interpreter (uv, Poetry, `.venv`,
`MODEL_WTF_PYTHON`) and its `DJANGO_SETTINGS_MODULE` (env, `manage.py`,
`[tool.model-wtf] django_settings`), then pipes its own stdlib-only
introspection script into it. Nothing generated is written to disk.

Each field gets three classifications from the built-in rules
(`model_wtf/knowledge/data_rules/`, first match by ascending priority):

- `pii` — personal data or not;
- `sensitivity` — ordinal: `public < internal < personal < confidential < special`,
  each level carrying a DPIA hint (`never`, `large_scale`, `always`);
- `category` — nominal, what the Art. 30 register will print (`identity`,
  `contact`, `financial`, `connection`, `location`, `behavioural`, `content`,
  `credentials`, `health`, `biometric`, `special_other`, `criminal`,
  `professional`, `technical`).

`JSONField`s are presumed to hold personal data (`confidential`, `content`)
until a review says otherwise; unrecognised plain fields default to
`technical` and rely on the review to be promoted.

Humans correct the rules with `<unit>/compliance/data/<app.Model.field>.yaml`
(any subset of `pii` / `sensitivity` / `category` / `store`, plus a `reason`),
and add data the ORM does not know with a complete manual item
(`description`, `pii`, `sensitivity`, `category`, optional `store`) under any
other id.

`init --custom-sensitivity` / `--custom-categories` copy the built-in scale
or category list into `compliance/sensitivity/` / `compliance/categories/`
for editing; a renamed entry declares `replaces: [<built-in id>]` so the
rules still resolve, and `check` verifies every built-in id is covered once.

### Review

The inventory is virtual, so what has been looked at is tracked in
`<unit>/compliance/data.lock.yaml` (fingerprint of the field facts *and* of
the verdict, who, when, note). `data list` shows a `Review` column
(`pending:new`, `pending:changed`, `reviewed`, `override`, `known`) and
`--pending` filters on it; `check` fails with exit 1 while
anything is pending.

- `data reviewed <unit>:<id>... [--note TEXT]` — a human confirms the current
  classification.
- `data override …` also marks the item reviewed.
- Third-party models are reviewed like the project's own: what a task queue
  or a user table holds is this project's data. Curated verdicts for framework
  fields whose meaning is fixed (`auth.User.password`, …) live in
  `knowledge/known_fields.yaml` (`known`).
- Every file field also yields `<field>@files.content`: the bytes in the
  storage behind the column, classified on their own.

### Stores

```
uv run model-wtf compliance stores list [--unit ID] [--all] [--format table|json]
uv run model-wtf compliance stores explain <unit>:<slug>
```

Where the data lives is an item with a slug, and every data row references one
in its `Store` column. A store is a slug, a `type` and a conceptual `backend`
(`postgresql`, `redis`, `s3`, `filesystem`, ...) — nothing environmental:
hosts, bucket names and credentials belong to a deployment, not to the model
of the application. Stores are read from the Django settings, so there is
nothing to write for the common case: `DATABASES[alias]` → `db-<alias>` (rows
follow the router), `CACHES` → `cache-<alias>`, `STORAGES` → `files-<alias>`
(`bucket` when the backend is S3/GCS/Azure, else `filesystem`; `staticfiles`
skipped), a field's own `storage=` → `files-<app.Model.field>`,
`CELERY_BROKER_URL` → `queue-celery`, `WAGTAILSEARCH_BACKENDS` →
`search-<alias>`.

Optional `<unit>/compliance/stores/<slug>.yaml` files can override facts of an
introspected store (`backend`, `name`, `provider`, `location` as a region or
country, `retention`, `description`), declare a store the settings do not show
(`type: external`, `browser`, ... — `type` is then mandatory), or hide one
with `ignore: true`.
`check` reports `store-unknown` / `store-ignored-referenced` for data rows
naming a slug that does not exist or is hidden, and `store-orphan` for a
manual store file without `type`. `data override … --store <slug>` moves a
row to another store.

```
uv run model-wtf compliance data auto-review [--unit ID] [--base REF] [--batch 8] [--max-rounds 20] [--max-tokens N] [--model provider/model] [--dry-run]
```

Runs an OpenCode agent on OpenRouter (`openrouter/openrouter/auto` by default;
`OPENROUTER_API_KEY` required) until nothing is pending. The instance is
sandboxed (`model_wtf/opencode.py`): throwaway `HOME`/XDG tree, generated
config via `OPENCODE_CONFIG`, `--pure`, whitelisted environment, deny-all
permissions except read/glob/grep inside the repository and its interpreters'
import roots, our MCP server as the only write path; repository-level
`opencode.json` / `.opencode/` / `AGENTS.md` have no effect. Work is
dispatched one **model** at a time: `data_pending` → `data_model` (field
table + class source + JSON write sites) → `data_review_model` (all decisions
in one call), which keeps each subagent session small enough for flash-class
models. `--base REF` also re-dispatches models whose file changed since `REF`.

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
