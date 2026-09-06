---
name: compliance-folder
description: Layout and id conventions of a model-wtf compliance/ folder.
---

# The compliance/ folder

One folder per Docker image (unit), declared in `snow.yml` as
`images[].compliance`; a repo-root `compliance/` holds shared files
(controller, actors, assumptions, recipients). Resolution: unit first,
then root.

Every declaration is a **pair**: `<id>.gen.yaml` (machine facts, `by:
extractor|agent`, never edited by humans) and `<id>.yaml` (state:
agent-drafted with `drafted_by: agent`, then human-owned). **The file
name is the id**; there is never an `id:` key inside a file.

| Path | Kind | Id example |
| --- | --- | --- |
| `controller.yaml`, `security.yaml` | singletons | -- |
| `actors/<id>.yaml` | data-subject categories | `customers` |
| `assumptions/<id>.yaml` | facts findings may rely on | `edge-rate-limit` |
| `recipients/<id>.yaml` | processors / third parties | `stripe` |
| `processing/<id>.yaml` | activities | `billing.invoicing` |
| `data/<id>.yaml` | data objects | `billing.invoices` (`app_label.slug`) |
| `elements/<kind>.<id>.yaml` | checkpoint ledger | `recipient.stripe` |
| `findings/F-NNNN.yaml` | one failed checkpoint | `F-0042` |

Element stable ids: `http:POST:/back/api/leads/`, `task:app.tasks.purge`,
`store:app.Model`, `egress:host:api.stripe.com`, `data_object:<id>`,
`activity:<id>`, `recipient:<id>`. A checkpoint key is `RULE@stable-id`.

A value a human still has to provide is written as the YAML tag `!open`
(optionally with a hint: `dpa_reference: !open ask legal`). Never write the
word "open" as a placeholder string.

Checkpoint statuses: `unknown` (to evaluate), `ok` (with `evidence` and
`depends_on`), `not_ok` (with a finding), `n_a` (with `reason`),
`accepted` (human decision on the finding). You never write any of these
files; you report, model-wtf writes.
