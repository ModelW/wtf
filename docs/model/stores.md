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
`search-<alias>`.

Optional `<unit>/compliance/stores/<slug>.yaml` files can override facts of an
introspected store (`backend`, `name`, `provider`, `location` as a region or
country, `retention`, `description`), declare a store the settings do not show
(`type: realtime`, `external`, `browser`, ... — `type` is then mandatory), or
hide one with `ignore: true`. A declared store may list `hosts`: the
hostnames or the *settings names* (`TMW_URL`, `EMAIL_HOST`) the code reaches
it by. A touchpoint whose code reads such a setting is then a store write to
it (declared with the manifest's `stores:`), not a transfer to an unknown
host — the way to model a service the project runs itself (a Hocuspocus
board, a search index) or infrastructure whose operator is only known at
deployment (the SMTP relay: `type: external`, `provider: !todo`).
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
