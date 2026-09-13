# Stores

Where the data lives: databases, caches, buckets, queues, search indexes. Introspected from settings; one file per store carries what a human knows (provider, location, retention) and the threat stamps on it.

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
`search-<alias>`, `mail-default` (type `mail`) in every Django unit, and
`errors-sentry` (type `monitoring`) wherever `sentry_sdk` is installed.

Outgoing email and error monitoring are stores of the application, not
parties: the code hands a message to Django's mail API or an exception to
`sentry_sdk`, and which backend, relay, provider or Sentry instance (cloud,
self-hosted) receives it is infrastructure, reviewed at another level — no
distinction is made between backends. `mail-default` claims the
`EMAIL_BACKEND` / `EMAIL_HOST` setting names and a `send_mail` /
`EmailMessage` / `email_user` call is reported as a write to it
(`setting:EMAIL_BACKEND`); `errors-sentry` claims the `sentry_sdk` client
and `SENTRY_DSN`, and a `capture_exception` is a write to it. Both are
undeclared until the touchpoint lists the copy under `stores`. `party_add`
refuses a party that names one of them (`Sentry`, `SMTP mail server`,
a party whose `hosts` claim `EMAIL_HOST`): it is a store write.

Optional `stores` rows (`store_add`) can override facts of an
introspected store (`backend`, `name`, `provider`, `location` as a region or
country, `retention`, `description`), declare a store the settings do not show
(`type: realtime`, `external`, `browser`, ... — `type` is then mandatory), or
hide one with `ignore: true`. A declared store may list `hosts`: the
hostnames or the *settings names* (`TMW_URL`, `CDN_PURGE_URL`) the code
reaches it by. A touchpoint whose code reads such a setting is then a store
write to it (declared with the declaration's `stores`), not a transfer to an
unknown host — the way to model a service the project runs itself (a
Hocuspocus board, a search index) or infrastructure whose operator is only
known at deployment (`type: external`, `provider: !todo`).
`check` reports `store-unknown` / `store-ignored-referenced` for data rows
naming a slug that does not exist or is hidden, and `store-orphan` for a
manual store row without `type`. `data override … --store <slug>` moves a
row to another store.

One store is one row. `store_add` refuses a manual store that looks like a
visible store of the unit — a shared host or settings name, a name that
normalises to an existing one's (or to a config store's slug or backend:
"Sentry SDK ingest" is `errors-sentry`), a slug that contains or respells
one — and names the slug to reuse. The refusal is final for an agent. A
human resolves the rare real case on the command line: `stores distinct
<unit:slug> <slug>` records that two lookalikes are different stores,
`stores merge <unit:slug> --into <slug>` folds one into the other (writes,
item placements and stamps move). Lookalikes that already coexist are a
`store-duplicate` error. Two introspected stores never flag each other:
they are what the settings say.

```
uv run model-wtf compliance stores list [--unit ID] [--all] [--format table|json]
uv run model-wtf compliance stores explain <unit:slug>
uv run model-wtf compliance stores add <unit:slug> --type T --name N [--backend B] [--host H]... [--distinct-from SLUG]...
uv run model-wtf compliance stores set <unit:slug> [--name N] [--provider P] [--location L] [--retention R] [--host H]... [--ignore] [--clear FIELD]...
uv run model-wtf compliance stores remove <unit:slug> [--force]
uv run model-wtf compliance stores merge <unit:slug>... --into <slug>
uv run model-wtf compliance stores distinct <unit:slug> <slug>...
```

```
uv run model-wtf compliance data auto-review [--unit ID] [--base REF] [--batch 8] [--workers 16] [--max-rounds 20] [--max-tokens N] [--model provider/model] [--dry-run]
```

Runs an OpenCode agent (`openrouter/openrouter/auto` with `OPENROUTER_API_KEY`
by default; Scaleway's serverless APIs or a dedicated deployment with
`SCALEWAY_SECRET_KEY`, see [the swarm guide](../guides/swarm.md#model-and-cost))
until nothing is pending. The instance is
sandboxed (`model_wtf/opencode.py`): throwaway `HOME`/XDG tree, generated
config via `OPENCODE_CONFIG`, `--pure`, whitelisted environment, deny-all
permissions except read/glob/grep inside the repository and its interpreters'
import roots, our MCP server as the only write path; repository-level
`opencode.json` / `.opencode/` / `AGENTS.md` have no effect. Work is
dispatched one **model** at a time: `data_pending` → `data_model` (field
table + class source + JSON write sites) → `data_review_model` (all decisions
in one call), which keeps each subagent session small enough for flash-class
models. `--base REF` also re-dispatches models whose file changed since `REF`.
