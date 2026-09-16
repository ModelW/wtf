# Units and the database

A repository is a set of **units** (the images of `snow.yml`, or the entries of `.model-wtf.yml`), each with its own codebase, plus one SQLite database at the repository root, `compliance.db`, holding everything a human or an agent declares — for the product as a whole and for each unit.

The database is committed like any other file. It is tuned to diff well
(WAL journal, no auto-vacuum, a checkpoint on every close) and the
transient sidecars (`*.db-wal`, `*.db-shm`, `*.db-lock`) are ignored by git.
Nothing generated is stored: models, routes and stores from the settings
are introspected from the code on every run. The schema is versioned
(`PRAGMA user_version`): a database written by an older release is
migrated in place the first time a newer one opens it, and a file from a
newer release is refused rather than misread.

- the `app` row — `name`, `description`, `controller` (party id, the
  client), optional `processor` (party id, the agency), `large_scale`
  (Art. 35(3)(b); absent means no: a DPIA is then only required for
  special-category data; `!todo` asks the question once).
- `parties` — one row per organisation: `name`, `country` (ISO alpha-2),
  `address`, `email`; optional `phone`, `website`, `hosts` (API hostnames the
  code calls when they differ from the website, e.g. `api.hubapi.com`: a
  call to one is a transfer to this party), `registration`, `dpa`
  (where the processing agreement lives), `safeguard`/`dpf_certified`,
  `dpo` and `representative` contact blocks, `distinct_from` (ids of
  parties this one resembles but is not). A party is role-less:
  controller, processor or recipient is decided per processing activity. A
  party nothing refers to (no transfer, no role, no `recipients`) is a Todo.
  One organisation is one row: `party_add` refuses a party whose name
  normalises to a declared one's (case, accents, punctuation and legal
  forms such as `Inc`, `SAS`, `GmbH` ignored; a word added or a typo in a
  long name still matches), whose website or `hosts` share a registrable
  domain or a setting name with one, or whose id is a respelling of one;
  it also refuses a party that is really a store of the project (`Sentry`,
  an "SMTP mail server", a party claiming `EMAIL_HOST`). The refusal is
  final for an agent. A human resolves the rare real case on the command
  line: `parties distinct <id> <id>` records that two lookalikes are two
  organisations (Mailgun and Mailjet), `parties merge <id>... --into <id>`
  folds duplicates into one (transfers, recipients, roles, stamps move;
  the winner's `!todo` facts take the losers' answers), `parties to-store
  <id> <unit:slug>` turns a party that was infrastructure into store
  writes, `parties to-flow <id>` drops a party that was the project itself
  (its own endpoint: the edge is the derived `calls` flow, nothing leaves).
  Two lookalikes that already coexist are a `party-duplicate` error in
  `check`.

```
uv run model-wtf compliance app show [--format table|json]
uv run model-wtf compliance app set [--name N] [--description D] [--controller ID] [--processor ID] [--large-scale|--no-large-scale] [--todo FIELD]... [--clear FIELD]...
uv run model-wtf compliance parties list [--unused] [--format table|json]
uv run model-wtf compliance parties show <id> [--format text|json]
uv run model-wtf compliance parties add [<id>] --name N [--country CC] [--website URL] [--host H]... [--distinct-from ID]...
uv run model-wtf compliance parties set <id> [--name N] [--country CC] [--address A] [--email E] [--safeguard S] [--host H]... [--todo FIELD]... [--clear FIELD]...
uv run model-wtf compliance parties remove <id> [--force]
uv run model-wtf compliance parties merge <id>... --into <id>
uv run model-wtf compliance parties to-store <id> <unit:slug>
uv run model-wtf compliance parties to-flow <id>
uv run model-wtf compliance parties distinct <id> <id>...
uv run model-wtf compliance parties duplicates [<candidate-id> --name N] [--all]
```


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
