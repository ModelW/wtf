# Touchpoints

The entry points through which data moves: HTTP routes, background tasks, admin screens, front-end routes. Each one declares what it does to which items (the **ops**), for whom (the **scope**) and what it sends to other organisations (the **transfers**).

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
lists what leaves to another organisation's API — `- {party: mapbox, data:
[...], purpose: ...}`, the party being a `compliance/parties/` id, which is
where the register's recipients come from (`exporting:` still loads, with a
deprecation warning); plus `ignore`, `note`. The project's own database,
file storage, cache and queue are *stores*, not transfers, whoever hosts
them: hosting is a separate layer, taken as adequate here. Every inventory item the code
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
