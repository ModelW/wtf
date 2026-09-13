# Changelog

One section per released version, newest first. The release workflow puts
the matching section on the GitHub release.

## 1.2.0

- **Storage moves from YAML to SQLite.** Every declaration — the app, the
  parties, data overrides and reviews, touchpoint declarations, stores,
  activities, threat stamps, the findings register, custom vocabularies
  and actors — lives in one `compliance.db` at the repository root; the
  `compliance/` folders are gone and `snow.yml`'s `compliance:` block only
  names the discovery engine (`dir` is dropped). The database is tuned to
  diff well (WAL, no auto-vacuum, a checkpoint on close) and `init` adds
  its transient files to `.gitignore`. Cross-references (hosts, data refs,
  transfers, recipients, stamps, locks) are normalised tables queried with
  SQL rather than loaded and joined in Python. No migration from the YAML
  layout: it is a new system.
- The `CODEOWNERS` step of `init` (and its `check` diagnostic and flags)
  is removed.
- Marker subjects are `<record>#<field>` (`parties/acme#address`,
  `activities/ordering#retention`, `app#description`) instead of file
  names.
- The library takes the repository from a process-wide container set
  once per command (`--root`); no `root=` / `shared=` arguments.
- **Duplicate parties are refused.** `party_add` (and `init`) compare the
  new party with every declared one — normalised name (case, accents,
  punctuation, legal forms and a typo or an extra word ignored), shared
  registrable domain or setting name of the website / `hosts`, respelled
  id — and fail with the matching id when one looks the same. A party
  that names a store of the project (`Sentry`, "SMTP mail server", a
  host of `EMAIL_HOST`) is refused too: that is a store write. The
  refusal is final for agents; `distinct_from` is set by a human only.
  `check` reports coexisting lookalikes as a `party-duplicate` error.
- **Duplicate stores are refused** the same way: `store_add` compares the
  new store with the unit's visible ones (shared host / settings name,
  alike name, slug or config backend) and fails with the slug to reuse;
  `check` reports coexisting lookalikes as `store-duplicate`.
- **`parties` CLI**: `list`, `show`, `add`, `set`, `remove [--force]`,
  `merge ... --into`, `to-store <id> <unit:slug>` (a party that was
  infrastructure becomes store writes), `to-flow <id>` (a party that was
  the project itself: its transfers go, the derived call stays),
  `distinct`, `duplicates`.
- `auto-review` narrates each write once: the line comes from the activity
  log the MCP server appends to, no longer also from the tool-call stream
  (activities, parties and declarations were printed twice). Stores,
  undeclared-flow reports and challenges get a line too.
- A reported sink that names a store the way the party guard sees it
  (`sdk-sentry-sdk`, "Sentry error tracker", "the mail server") resolves
  to that store, so declaring the store write closes the report. Before,
  the sink stayed an unresolvable transfer: `party_add` refused the party
  (it IS the store) and the touchpoint could never leave pending.
- A relative `fetch("/api/x")` in a SvelteKit route is linked to the
  route of the project that serves it (a `calls` edge, like a generated
  client call) and leaves the outbound `fetches`: the project's own
  endpoints never show up as an unknown host to declare a party for.
  **`stores`** gains `add`, `set`, `remove`, `merge`, `distinct`.
- **Outgoing email and error monitoring are built-in stores.** Every
  Django unit has a `mail-default` store (type `mail`) claiming
  `EMAIL_BACKEND` / `EMAIL_HOST`, and an `errors-sentry` store (type
  `monitoring`) claiming `sentry_sdk` / `SENTRY_DSN` wherever the SDK is
  installed; a `send_mail` / `EmailMessage` / `email_user` call, or a
  `capture_exception`, is a write to them. How mail is sent and where
  events land (cloud, self-hosted) is infrastructure, so no distinction is
  made between backends: no more `smtp-*` stores or Sentry / mail provider
  parties declared by agents.
- `load_declarations` reads the parties even when the `app` row is
  missing, so `parties list` works before `init`.
- Fix: the unit's introspection no longer inherits `VIRTUAL_ENV` /
  `PYTHONPATH` / uv and poetry variables from the process running
  model-wtf. Under `uv run model-wtf`, `poetry run` in the unit honoured
  our `VIRTUAL_ENV` and imported the project in model-wtf's venv
  (`No module named 'celery'`), and `uv run` created a stray `.venv` and
  `uv.lock` in the unit.
- Schema migrations: `compliance.db` carries its schema version and is
  upgraded step by step (`model_wtf.compliance.migrations`) when a newer
  release opens it; a file from a newer release is refused.

## 1.1.0

- Scaleway as a model provider next to OpenRouter: `--model scaleway/<model>`
  for the serverless Generative APIs, `--model scaleway-dedicated/<model>`
  for a dedicated inference deployment of your own. Credentials come from
  `SCALEWAY_SECRET_KEY` and, for a deployment, `SCALEWAY_INFERENCE_ENDPOINT`;
  without `--model` the deployment is asked what it serves. The action takes
  `scaleway-secret-key`, `scaleway-inference-endpoint` and `model`.

## 1.0.0

The first release. `compliance init` scaffolds a repository; the four
inventories (data, touchpoints, flows, stores) are introspected from the
code and reviewed by agents or humans; activities, rights coverage and the
threat model are derived; `check` is the to-do list and `ghate` the gate on
every pull request, with a challenger agent that re-opens the reviews a
change undermines.

- Data inventory from Django models with rules, reviews, JSON contents and
  overrides (KFF-194–199).
- Touchpoints from Django URL confs, task registries and SvelteKit trees;
  declarations with ops, scope, transfers and store writes (`stores:` for
  the project's own second-tier stores, declared with `hosts`); activities and legal bases;
  rights coverage derived from ops × scope (KFF-200–208).
- The gate: `ghate` compares base and head by finding identity; the
  challenger re-opens data items, touchpoint declarations and threat stamps
  from the diff (KFF-205, KFF-210, KFF-217).
- Threats: pytm's 114 threats mapped, deterministic dismissal rules, a
  matrix over touchpoints, stores, parties and flows, stamps in the
  manifests, severity from effect × degree × sensitivity × actor, stable
  finding ids, a per-topic reviewer swarm (KFF-211–215).
- Flows as an inventory with kinds and statuses; undeclared transfers by
  construction from the hosts the code calls (KFF-216).
- `CODEOWNERS` entries at init (KFF-204); the documentation site
  (KFF-218); this release machinery (KFF-219).
