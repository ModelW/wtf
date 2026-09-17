# Changelog

One section per released version, newest first. The release workflow puts
the matching section on the GitHub release.

## 1.2.2

- **`data rights`.** A human records an exemption (`--exempt legal_obligation
  --note "..."`), a declared gap (`--missing --note`) or clears an entry on
  one right of one personal item (or a `Model.*` glob) from the command
  line; until now only the agents' `data_flag` tool could write the
  `rights` block.

## 1.2.1

- **Rights on a JSON content are read, not orphaned.** A reviewer's
  `data_flag` on `<field>@json.<name>` (a retention gap observed on one key
  of a blob) wrote an `override` row whose id names no column; `check`
  then reported it as a manual item lacking a description — an error the
  agents had no way to clear. The row is now the content's rights block:
  it lands on the declared content, needs the column's `contents`
  declaration (`data-orphan` otherwise), must name a declared content
  (`data-ref-unknown`) and a personal one (`rights-on-non-personal`).
- **`app set` / `app show` and `activities set`.** The `!todo` questions
  of the product row (`description`, `large_scale`, controller, processor)
  and of an activity (legal basis, consent record, interest, retention,
  data subjects, recipients...) are answered from the command line, like
  `parties set`; `--todo FIELD` reopens one, `--clear FIELD` drops an
  optional one. No more editing the database by hand.
- Docs: the add-to-project guide no longer says "edit the YAML" and
  explains that activity grouping is the second pass of `touchpoints
  auto-review` (`--group`), not a command of its own.

## 1.2.0

- **The gate installs the base's environment when the lock differs.** A
  pull request that changes `uv.lock` / `pnpm-lock.yaml` used to leave the
  base worktree without a `.venv` / `node_modules`; `uv run --no-sync`
  then created an empty venv and introspection died with
  `ModuleNotFoundError: No module named 'django'` — a tool error that
  failed the whole gate. The base's environment is now built from its own
  lock (`uv sync --frozen --no-dev`, `pnpm install --frozen-lockfile`,
  ...) inside the worktree; only when that is impossible does the base
  run approximate, with a warning.
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
- **Reach: who the code lets in, apart from who it serves.** A finding's
  likelihood used to come from the touchpoint's `scope`, so a `system`
  webhook listing whose `get_permissions()` returned `[]` on the leader —
  readable by anyone on the internet — scored `info` (system, 0.01)
  instead of `high` (anonymous). Touchpoints now carry a `reach`
  (`anonymous | subject | staff | system`), inferred from the auth facts
  alone (no auth is anonymous whatever the scope says) and declared by the
  reviewer through `touchpoint_set_data(reach=)`. The Django introspection
  reports `auth_custom` — DRF views overriding `get_permissions`,
  `get_authenticators`, `dispatch`… or using a hand-written authentication /
  permission class — and such a touchpoint is pending until a reviewer
  reads the override and declares its reach; the declaration is refused
  without it. Schema v4 adds `touchpoints.reach`.
- **Severity buckets rebalanced.** `critical` is an open buffet — anyone
  (or any account onto every other account's data) takes personal data in
  bulk, a confidential listing or a special-category record; `high` is
  what takes some work, or an account, to get at what is not yours;
  `medium` is what someone could do that they should not. Concretely: the
  `bulk` degree weighs 2 (each degree doubles the last), critical starts
  at 4, high at 2, medium at 1; every reviewable threat in `_mapping.yaml`
  declares an `effort` (`open` walk in ×1, `work` a script or payload ×¾,
  `chain` another flaw or a victim ×½) that scales the likelihood, so a
  brute force on a login or a stored XSS is `high`, not `critical`; the
  ownership threats (AA03, AC01, AC07, AC12, DS05) are `horizontal` — a
  subject who can read every other subject's rows weighs like an anonymous
  caller; the oracle threats (DS01, INP18) are capped at one `attribute`
  and fingerprinting (DS03, HA03) at `existence`, whatever the touchpoint
  lists; escalation weighs like a disclosure of the data the touchpoint
  handles (floor 2) instead of a flat 4, so an unauthenticated webhook that
  creates one record is `high` and an unauthenticated confidential listing
  `critical`; a tampering on a touchpoint that only creates is one
  `record`; denial of service is a flat 1 whatever the data behind the
  endpoint (an outage is an incident, not a breach), so an unthrottled
  public endpoint is `medium`, not `high`. A touchpoint's write into an internal store of the project
  (`own_store_write`: database, files, cache, queue, search, realtime) no
  longer carries the leak cells DS06/DR01 — the response to the caller and
  the mail / monitoring / external flows keep them.
- **Reach is derived through the front.** A SvelteKit route with no auth
  of its own takes the reach of the api touchpoints it `calls` (the
  cookie is forwarded: whoever the api lets in) and of a parent
  `+layout.server.ts` that redirects unauthenticated callers to login (the
  introspection reports such a `load` as a `login guard` auth fact). The
  `api.bizneo(fetch).opId()` client-factory call style is now recognised,
  and DRF routes carry drf-spectacular's operation ids, so front routes
  link to the DRF endpoints they proxy.
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
