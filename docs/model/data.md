# Data items

Every field, column, JSON key and file content the application holds, with three classifications: personal or not, a sensitivity level, a category. The inventory comes from the ORM; the classifications from rules, then from reviews.

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


## JSON-like columns hold contents


A `JSONField` / `ArrayField` / `HStoreField` (not Wagtail's `StreamField`,
which is CMS content) is a container: one triple cannot describe a blob
holding a name, an address and an IBAN. Its file declares what it holds,
one entry per **kind** of information (identifiers, not JSON paths):

```yaml
contents:
  customer_name: {pii: true, sensitivity: personal, category: identity}
  iban:          {pii: true, sensitivity: confidential, category: financial}
  utm_campaign:  {pii: false, sensitivity: internal, category: technical}
unknown_contents: none     # none | possible | likely — is the list exhaustive?
reason: written in orders/services.py:88-104 and checkout/serializers.py:41
```

Each entry becomes a row `<app.Model.field>@json.<name>` reviewed and
overridable on its own; the column's verdict is **derived** (`pii` = any,
`sensitivity` = max, `category` = the set as `financial+identity+technical`,
DPIA = max). `unknown_contents: none` replaces the rule's presumption,
`possible` keeps a `json-unknown-contents` warning, `likely` folds the
presumption back in (so `contents: {}` + `likely` = "opaque, treat as
personal"). `data contents <unit:id> name=yes,personal,contact ... [--unknown none]
[--reason ...]` writes the file; the auto-review never closes a JSON-like
field with a bare `ok`: it follows the write sites `data_model` lists and
declares the contents itself.

Humans correct the rules with `<unit>/compliance/data/<app.Model.field>.yaml`
(any subset of `pii` / `sensitivity` / `category` / `store`, plus a `reason`),
and add data the ORM does not know with a complete manual item
(`description`, `pii`, `sensitivity`, `category`, optional `store`) under any
other id.

`init --custom-sensitivity` / `--custom-categories` copy the built-in scale
or category list into `compliance/sensitivity/` / `compliance/categories/`
for editing; a renamed entry declares `replaces: [<built-in id>]` so the
rules still resolve, and `check` verifies every built-in id is covered once.


## Review


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
  or a user table holds is this project's data. What model-wtf already knows
  about them lives in `knowledge/library/<app.Model>.yaml`: per field a
  default verdict with `fixed: true` when the framework fixes the meaning
  (`auth.User.password` — source/status `known`, nothing to review) or
  `fixed: false` when it depends on the project (`ProcrastinateJob.args`,
  `Session.session_data`, `FormSubmission.form_data` — source `library`,
  status `pending:assumed`). Assumed models carry an `assumption` and a
  `check`: what we take for granted and what to look at in *this* project;
  `data list` prints the assumption under the row (`--assumed` filters on
  them), `data_model` shows it to the agent (which must do the check before
  confirming); `check` only counts them in the pending breakdown
  (`37 data item(s) pending (12 new, 9 assumed, 16 contents)`).
  `fields_default` covers unlisted columns of tables that are technical
  through and through.
- Every file field also yields `<field>@files.content`: the bytes in the
  storage behind the column, classified on their own.
