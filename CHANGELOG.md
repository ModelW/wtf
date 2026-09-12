# Changelog

One section per released version, newest first. The release workflow puts
the matching section on the GitHub release.

## Unreleased

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
