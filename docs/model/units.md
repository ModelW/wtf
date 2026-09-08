# Units and files

A repository is a set of **units** (the images of `snow.yml`, or the entries of `.model-wtf.yml`), each with its own `compliance/` folder next to the code, plus the shared root `compliance/` for what belongs to the product as a whole.

- `compliance/app.yaml` — `name`, `description`, `controller` (party id, the
  client), optional `processor` (party id, the agency), `large_scale`
  (Art. 35(3)(b); absent means no: a DPIA is then only required for
  special-category data; `!todo` asks the question once) and `owners`
  (`dpo`/`ciso` GitHub teams for `CODEOWNERS`).
- `compliance/parties/<id>.yaml` — `name`, `country` (ISO alpha-2),
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
