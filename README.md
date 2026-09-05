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

## Development

```
uv sync
make clean   # format + lint + typecheck
make test
```
