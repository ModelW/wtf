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
uv run model-wtf compliance check [--strict] [--allow-todo] [--todo] [-v] [--format text|json|github] [--root PATH]
```

`init` scaffolds the repo-root `compliance/` folder (`app.yaml`, one
`parties/<id>.yaml` per organisation, a README), adds a `compliance:` block to
every image of `snow.yml` (guessing the discovery backend from the code) and
creates the per-unit folders. It never
overwrites anything; re-run it to add what is missing. Values left for a human
are written as the YAML tag `!todo`. The processor defaults to
`default_processor: {name, country, address, email}` from
`~/.config/model-wtf/config.yml`.

`check` is the to-do list. It discovers the units, validates every
declaration file against its schema (pydantic; unknown keys are errors) and
groups what it finds by the kind of work it asks for:

```
Errors — fix the files                                  exit 3
Missing — non-compliant code or process, to build       exit 1, never ignorable
Todo — questions only a human can answer                exit 1 (--allow-todo → 0)
Review — run the agents, or decide                      exit 1
Info                                                    (-v for the details)
```

One line per thing to do, with the command that resolves it after an arrow;
marker findings are folded per file (`parties/fah.yaml: address, email`).
`check --todo` prints only the open questions, one per line with the
question the field asks, so the list can be handed to whoever holds the
answers. `--format json` groups under `sections` with a stable `subject`
per entry (`app.yaml#description`, `api:data`) that a gate can diff between
runs; `--format github` maps Errors/Missing to `error`, Todo/Review to
`warning`, Info to `notice`.

Two YAML tags mark a value deliberately left open, both with an optional
note: `!todo` (the analysis has not been conducted) and `!missing "no purge
task, see FAH-210"` (it has, and the code or process is not there — an
established non-compliance, which always fails the gate).

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

### JSON-like columns hold *contents*

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
uv run model-wtf compliance data auto-review [--unit ID] [--base REF] [--batch 8] [--workers 16] [--max-rounds 20] [--max-tokens N] [--model provider/model] [--dry-run]
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

### Touchpoints

```
uv run model-wtf compliance touchpoints list [--unit ID] [--pending] [--all] [--format json]
uv run model-wtf compliance touchpoints show <unit>:<id>
uv run model-wtf compliance touchpoints set-data <unit>:<id> [<unit>:<item>[=read|write]...] [--add|--remove] [--ignore] [--note ...]
```

Vocabulary, kept clear of pytm's: a **unit** is a running component (pytm
*Process*); a **touchpoint** is one of its entry points through which data
flows (pytm *Dataflows*); an **activity** is a GDPR processing activity. The
word "process" is not used.

Touchpoints are introspected, never written: Django URL patterns (id = route
name, or `METHOD /path`; Ninja endpoints by operation id with their
request/response schemas flattened from the API's own OpenAPI document, DRF
serializers, `FormView` fields, auth classes), Procrastinate/Celery tasks
(`task:<name>`, signature, periodic flag, tasks they defer) and admin screens
(`admin:<app.Model>`, the fields staff see). SvelteKit units run `svelte-kit
sync` and read the generated `$types.d.ts` with the project's own TypeScript:
id = route ID, `RouteParams`, `PageData`/`ActionData` shapes, form field
names, and the generated-API-client operations the route calls — which link
to the Django touchpoints by operation id (`calls`). Plumbing (health checks,
OpenAPI documents, the admin's own URL patterns) is ignored by default.

The optional manifest `<unit>/compliance/touchpoints/<slug>.yaml` declares
what the touchpoint **does** to data, with a closed vocabulary of **facts**
(`src/model_wtf/compliance/ops.py`): each `data:` entry is a ref (`@json`/
`@files` rows allowed, `unit:app.Model.*` for a whole model) and its ops —
a bare `- unit:app.Model.field` is a `read`, `- ref: create`, `- ref: [create,
read]`, `- ref: {delete: {mode: anonymise}}`, `- ref: {retention_purge:
{after: settings.ANONYMOUS_ADDRESS_MAX_AGE, since: last use, when: anonymous
only}}`. Verbs: `create[{consent_for}]`, `read`, `update`, `delete[{mode}]`,
`retention_purge{after (duration or setting name), since, when?}`,
`portability{format}`, `consent_withdraw{for}`; each verb takes only its own
metadata. No legal verb: a person changing their own address is an `update`,
deleting it a `delete` — what that means for their rights follows from the
touchpoint's **scope** (`scope: subject | staff | public | system`, inferred
from auth classes, `request.user` in the body and admin namespaces, or
declared in the manifest). `write`, `rectify`, `access`, `erase`, `object`,
`restrict` still load, folded onto the fact they imply with an
`op-ambiguous` warning. `transfers:`
lists what leaves to another organisation — `- {party: mapbox, data: [...],
purpose: ...}`, the party being a `compliance/parties/` id, which is where
the register's recipients come from (`exporting:` still loads, with a
deprecation warning); plus `ignore`, `note`. Every inventory item the code
touches is listed, personal or not: the register filters on `pii`
downstream, the data-flow model needs all of it. A touchpoint is
**pending** until it has a `data` key — an explicit `[]` means "touches no
inventory item, checked". `check` reports `touchpoint-pending` and
`touchpoint-orphan` (handles personal data, belongs to no activity), both
exit 1, and `data-unreferenced` as information.

Introspection pre-fills **likely ops** (`touchpoints show` → "likely ops"):
HTTP method (`POST` → create, `PUT/PATCH` → update|rectify, `DELETE` →
delete|erase), Django admin permissions (`has_*_permission` overrides,
`readonly_fields`, `list_display`), task names (`purge|clean|expire`,
`anonymi[sz]e|erase|gdpr`, `export`) and task bodies (`.delete()`,
`.update()`, `timedelta(days=30)` as an `after` hint), SvelteKit handlers and
action names. The reviewer confirms them against the code. `data why`
prints each item's lifecycle from the ops: *created by api:signup, read by
6, rectified by admin:people.User (by staff), never erased, purged by
api:task:cart.purge (after days 30, ...), sent to mapbox*.

```
uv run model-wtf compliance touchpoints auto-review [--unit ID] [--batch 8] [--workers 16] [--max-rounds 20] [--group/--no-group] [--group-only] [--model ...] [--max-tokens N]
```

Same sandboxed OpenCode loop as `data auto-review` (`--workers` sessions run in
parallel each round, each on its own shard of the pending list), two passes. **Pass 1**,
one touchpoint per subagent session: `touchpoint_show` gives the code
location, the schemas and what the API operations it calls already declare;
the reviewer reads the view/task/route, resolves items with `data_search`
(never typing an id it did not see), creates a **manual item** with
`data_add_manual` for personal data the ORM has no row for — transient
(a card number forwarded to the PSP, a position sent to a geocoder, a search
query) or kept outside the ORM; processing counts even without storage,
while non-personal transient values are not tracked — and closes
with one `touchpoint_set_data` call citing file:line (`[]` = touches nothing
personal). **Pass 2**, once nothing is pending (or right away with
`--group-only`): a single session reads `activities_graph` — every
PII-touching touchpoint with its categories, `calls`/`defers` edges and
current activity — and follows the chains front → api → task to
`activity_create` / `activity_add_touchpoints`; `legal_basis` only when
evident, `retention` and the rest stay `!todo` for a human, existing
activities are never emptied.

### Activities

```
uv run model-wtf compliance activities list [--format json]
uv run model-wtf compliance activities explain <slug>
uv run model-wtf compliance activities create <slug> [--name] [--purpose] [--legal-basis] [--touchpoint unit:id]... [--subject]... [--recipient]... [--retention]
uv run model-wtf compliance activities add <slug> <unit:id>...
uv run model-wtf compliance data why <unit:id>... [--model unit:app.Model] [--manifests] [--format json]
```

`compliance/activities/<slug>.yaml` (repository root, activities span units)
is the Art. 30 row: `name`, `purpose`, `legal_basis` (`consent | contract |
legal_obligation | vital_interests | public_task | legitimate_interests`, or
`no_pii` — a claim that the activity handles no personal item, verified at
every check: `no-pii-violated` otherwise), `data_subjects`, `touchpoints`,
`recipients` (party ids), `controller`/`processor` (default: `app.yaml`'s);
`consent: {record: <ref>, granularity: separate|bundled}` for consent-based
ones (the stored proof, created with `create: {consent_for: <slug>}`),
`interest` for legitimate interests (the balancing test), `basis_note` when
two bases compete, `dpia_reference` when the derived trigger fires. Any of
them may be `!todo` or `!missing "why"`. Everything else is **derived** from
the touchpoints: the data items, hence categories, stores, maximum
sensitivity, DPIA trigger, units, recipients and the ops per item. Retention
is not a field: the policy is the `retention_purge` op in the code.

### Rights coverage

Nothing about rights is written on activities. Touchpoints state what the
code does (ops), data items state what is true of the data regardless of
code, activities carry purpose and basis; `check` derives, **per personal
item in every activity that handles it**, whether each right is served
(`src/model_wtf/compliance/rights.py`):

| right | satisfied when | code |
| -- | -- | -- |
| access (Art. 15) | a `subject`-scoped touchpoint `read`s it | `access-missing` |
| rectification (Art. 16) | only for values the person provided: a `subject` `update`, or delete + create (re-creation) | `rectification-missing` |
| erasure (Art. 17) | a `subject` `delete`; `mode: anonymise` needs a ground to keep the row; `legal_obligation` activities exempt by construction | `erasure-missing` |
| storage limitation (Art. 5(1)(e)) | a `retention_purge` covering all rows, or purge cases + a delete path for the rest; a staff/system `delete` also ends the row's life | `retention-missing` |
| portability (Art. 20) | consent/contract, values the person provided, access served: a `portability` op or a JSON API the person calls on their own data | `portability-missing` |
| objection (Art. 21) | legitimate-interests activities: a `subject` update/delete on one of its items (an opt-out) | `objection-missing` |
| consent (Art. 7) | consent activities: `consent.record` created with `consent_for`, and a `consent_withdraw: {for: slug}` op | `consent-proof-missing`, `consent-withdrawal-missing` |
| transfers (Ch. V) | party outside the EEA / adequacy list (`knowledge/adequacy.yaml`) carries `safeguard: sccs|bcr|dpf|derogation` (`dpf` with `dpf_certified: true`); an unknown country is a Todo | `transfer-safeguard-missing` |
| DPIA (Art. 35) | special-category data (`always`) → `dpia_reference` on the activity; `large_scale` (confidential data) is a Todo question | `dpia-missing` |

When a staff screen performs the op but no self-service does, the finding
says so (*no self-service; staff can via admin:people.User — exempt
staff_only if a request process exists*). When every activity holding an
item is about `staff`/`employees`, the back-office is the person's own
interface and staff ops count as the subject's. Transient manual items
(`transient: true`) have no storage-side rights, only transfers. Library
models ship their own rights story (`knowledge/library/*.yaml` `rights:`
block: an audit trail is kept for accountability, a session is purged by the
framework) which applies to inherited columns too (a page type's `owner`).

Exemptions live on the **data item** (`<unit>/compliance/data/<id>.yaml`, or
`<app.Model>.*.yaml` for every personal field of a model; the item's own
file wins right by right):

```yaml
rights:
  erase: {exempt: legal_obligation, note: "accounting records, 10 years"}
  portability: {exempt: derived}
  rectify: {exempt: staff_only}           # verified: an admin op by staff must exist
  access: {exempt: manual, note: "..."}   # always listed under Review
  retention: !missing "no purge task, see FAH-210"
```

Grounds: `legal_obligation`, `contract_active` (still needs an event-driven
`erase`), `not_provided_by_subject` (portability), `derived`
(rectify/portability), `staff_only`, `manual`, `public_interest`, `research`,
`legal_claims`. Precedence for a right: item exemption → derived from ops →
missing. Every unmet right lands in the **Missing** section tagged with its
origin — `[derived]` (the tool), `[claimed]` (an agent that read the code,
via `data_flag` or a `{"missing": ...}` verdict in `activity_create`; the
note is prefixed `[agent]`), `[declared]` (a human's `!missing`) — and
`data why` prints each right's status next to the item's lifecycle.

### Exit codes

| Code | Meaning                                                              |
| ---- | -------------------------------------------------------------------- |
| 0    | Clean (or only `!todo` questions, with `--allow-todo`)               |
| 1    | Missing (`!missing`, never ignorable), Todo (`!todo`), Review (pending data / touchpoints, orphans) |
| 2    | Stale attestation                                                    |
| 3    | Declaration errors (schema, missing files, dangling party ids)       |
| 4    | Tool error                                                           |

## Development

```
uv sync
make clean   # format + lint + typecheck
make test
```
