# `model-wtf`

The Model W Transformation Facilitator is a CLI tool that facilitates Model W
compliance of a given Git repo.

## Compliance

### Getting started

```
uv run model-wtf compliance init [--unit ID]... [--codeowners-team @org/team] [--yes]
```

Creates a `compliance/` folder next to each image's Dockerfile (structure +
`security.yaml`/`controller.yaml` stubs with `open` markers, default actors, a
README), adds `compliance: compliance` to each `snow.yml` image (comments and
ordering preserved), and appends `/<context>/compliance/ @<org>/dpo` to
CODEOWNERS. Without `snow.yml`, units are detected from Dockerfiles into
`.model-wtf.yml` after confirmation. Idempotent: never overwrites.

```
uv run model-wtf compliance check [--strict] [--format text|json|github] [--root PATH]
                                  [--framework gdpr|stride|all] [--no-write]
```

Discovers the repository's compliance _units_, validates their declaration
files, and runs the deterministic **gates** of the rule engine on every element
(data object, activity, recipient). Gate verdicts are written to the checkpoint
ledger `elements/<kind>.<id>.yaml` (with `evaluated.by: engine`), applicability
to `elements/<kind>.<id>.gen.yaml`, and each failing gate gets a
`findings/F-NNNN.yaml` that is deleted when the gate passes again. `verify`
rules are seeded as `unknown` for the agent. `--no-write` reports without
touching the tree.

### Checkpoints and findings

A checkpoint is one `(element, rule)` pair, keyed `RULE@kind:id`. Its status
(`unknown | ok | not_ok | n_a | accepted`) lives in the element's ledger; a
`not_ok` has a `findings/F-NNNN.yaml` twin (numbers from `findings/.seq`,
committed, never reused). The lifecycle is deterministic
(`src/model_wtf/compliance/ledger.py`):

- new applicable rule → `unknown`; rule no longer applicable → entry dropped;
- Knowledge rule `version` bump → back to `unknown` (`staged_because`);
- a human deletes a finding file → its checkpoint goes back to `unknown`;
- a human adds an `accepted:` block (justification, `review_by`, optional
  assumption) to the finding → the checkpoint is `accepted`; `check` warns once
  `review_by` is past.

`check` judges the files: any `unknown` or unaccepted `not_ok` exits 1,
annotated at the finding's `provenance` under `--format github`
(`::error ... title=F-NNNN RULE::`). Fields still holding the `open` placeholder
from `init` are `::warning ... title=blank::`. When `$GITHUB_STEP_SUMMARY` is
set, a Markdown summary grouped by element is appended to it.

```
uv run model-wtf compliance gh-sync-comments [--pr N] [--repo owner/name] [--stage-report stage.json] [--budget-used $X]
```

Mirrors `findings/` onto the pull request through `gh api` (`GITHUB_TOKEN`): one
review comment per finding at its provenance (or on the finding file when the
provenance is outside the diff), marker `<!-- model-wtf F-NNNN -->`, updated in
place, thread resolved when the finding disappears; one summary comment
(open/accepted findings, blanks, agent budget, agent re-stages, how to accept)
edited across runs.

```
uv run model-wtf compliance stage [--base REF] [--element ID] [--rule ID] [--all] [--format text|json]
```

`stage` sends checkpoints back to `unknown` so `auto` re-evaluates them.
Mechanical triggers (no AI): new checkpoints, rule version bumps, deleted
findings, extracted `candidate_contents` nobody classified (→ `classify` list /
`GDPR-CLASSIFICATION-STALE`), explicit flags, and `.seq` conflicts against
`--base` (our findings are renumbered). With `--base`, code changes inside a
unit are handed to the staging **agent** (configured by `auto`), which returns
the checkpoints the diff plausibly invalidates (`staged_because: "ai: ..."`); a
unit already >50 % re-staged is re-staged whole instead. A docs-only diff yields
`empty: true` and no agent call.

```
uv run model-wtf compliance explain F-0042 | GDPR-PROCESSOR-DPA@recipient:stripe | recipient:stripe
uv run model-wtf compliance whitelist <paths...>   # what the bot may commit (exit 1 otherwise)
```

The bot (`auto`, the GHA commit step) may only write
`**/compliance/**/*.gen.yaml`, `**/compliance/elements/*.yaml`,
`**/compliance/findings/**` and _new_ files under `data/`, `processing/`,
`recipients/`. Everything else is a developer commit.

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

### Declaration files

Every file inside a compliance folder is validated against a schema
(`src/model_wtf/compliance/declarations/schemas.py`). **The file name is the
id**: `data/billing.invoices.yaml` declares the data object `billing.invoices`;
an `id:` key inside a file is an error. Element ids are projected onto a
path-safe form (`http:POST:/back/api/me/` →
`elements/http.POST.back.api.me.yaml`).

| Path                    | Kind                                    | Shared? |
| ----------------------- | --------------------------------------- | ------- |
| `controller.yaml`       | Controller + DPO/representative blocks  | yes     |
| `security.yaml`         | Art. 30(1)(g) general description       |         |
| `actors/<id>.yaml`      | Data-subject categories                 | yes     |
| `assumptions/<id>.yaml` | Environment facts findings may rely on  | yes     |
| `recipients/<id>.yaml`  | Processors / third parties / internal   | yes     |
| `processing/<id>.yaml`  | Activities: purpose, basis, recipients  |         |
| `data/<id>.yaml`        | Data objects: fields → items, retention |         |
| `elements/<id>.yaml`    | Checkpoint ledger (rule → status)       |         |
| `findings/F-NNNN.yaml`  | One open/accepted finding               |         |
| `<anything>.gen.yaml`   | Machine-written twin (`by: extractor`)  |         |

References from a unit to a _shared_ kind resolve in the unit folder first, then
in the repo-root `compliance/`. Every unknown reference (activity → recipient,
data object → actor, finding → assumption, ...) is a declaration error reported
with its `file:line`.

### Exit codes

| Code | Meaning                                                        |
| ---- | -------------------------------------------------------------- |
| 0    | Clean                                                          |
| 1    | Open findings / gate failures                                  |
| 2    | Stale attestation                                              |
| 3    | Declaration errors (missing/invalid manifest, `--strict` hits) |
| 4    | Tool error                                                     |

### Rendering

```
uv run model-wtf compliance render --format registry [-o registry.md]
```

Derives the Art. 30 record of processing activities as Markdown from the
declarations alone (no code, no AI): controller block, one section per activity
(purpose, lawful basis, data subjects, categories of personal data = union of
the linked data objects' items, recipients with third country/safeguards,
erasure time limits, derived rights matrix), recipients, data objects, and the
`security.yaml` TOMs description. Deterministic: same declarations →
byte-identical output. Templates are one Jinja file per kind under
`src/model_wtf/compliance/templates/registry/`.

## Knowledge

The rules, the data-item vocabulary and the egress catalogue live as YAML under
`src/model_wtf/knowledge/` (one file per rule/item/egress). `item:` values in
data-object declarations must be vocabulary items.

```
uv run model-wtf rules --list [--framework gdpr|stride|all]
uv run model-wtf rules explain GDPR-PROCESSOR-DPA
```

Every rule has `id`, `title`, `frameworks`, `applies_to: {kind, stack?}`,
`kind: gate|verify`, `severity`, `version`, `description`, `mitigation`,
`references`. Gates carry a `condition` (evaluated deterministically by the
engine); verify rules carry `evidence_hints` for the agent.

## Development

```
uv sync
make clean   # format + lint + typecheck
make test
```
