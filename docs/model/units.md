# Units and the database

A repository is a set of **units** (the images of `snow.yml`, or the entries of `.model-wtf.yml`), each with its own codebase, plus one SQLite database at the repository root, `compliance.db`, holding everything a human or an agent declares — for the product as a whole and for each unit.

The database is committed like any other file. It is tuned to diff well
(WAL journal, no auto-vacuum, a checkpoint on every close) and the
transient sidecars (`*.db-wal`, `*.db-shm`, `*.db-lock`) are ignored by git.
Nothing generated is stored: models, routes and stores from the settings
are introspected from the code on every run.

- the `app` row — `name`, `description`, `controller` (party id, the
  client), optional `processor` (party id, the agency), `large_scale`
  (Art. 35(3)(b); absent means no: a DPIA is then only required for
  special-category data; `!todo` asks the question once).
- `parties` — one row per organisation: `name`, `country` (ISO alpha-2),
  `address`, `email`; optional `phone`, `website`, `hosts` (API hostnames the
  code calls when they differ from the website, e.g. `api.hubapi.com`: a
  call to one is a transfer to this party), `registration`, `dpa`
  (where the processing agreement lives), `safeguard`/`dpf_certified`,
  `dpo` and `representative` contact blocks. A party is role-less:
  controller, processor or recipient is decided per processing activity. A
  party nothing refers to (no transfer, no role, no `recipients`) is a Todo.


## Unit discovery


Units are read from `snow.yml` at the repo root: every `images[]` entry that
carries a `compliance:` block is a unit. `discover` names the discovery backend
for that codebase (`django`, `sveltekit`, `none`) and is the only key: the
unit's code is the Dockerfile's folder, its declarations live in the
database. An image without `compliance` produces a warning (an error under
`--strict`).

```yaml
images:
    - id: api
      context: api                 # Dockerfile at api/Dockerfile
      compliance:
          discover: django         # code in api/
    - id: front
      context: .
      dockerfile: front/Dockerfile
      compliance:
          discover: sveltekit      # code in front/
    - id: docs
      context: .
      compliance:
          discover: none
```

Repos not deployed through Snow can use `.model-wtf.yml` instead
(`units: [{id, context, dockerfile, compliance}]`). When both files exist
`snow.yml` wins.

The product-level rows (the app, the parties, the activities, the findings
register) form the _shared_ scope; each unit's rows (data items, reviews,
touchpoint declarations, stores, stamps) its own.
