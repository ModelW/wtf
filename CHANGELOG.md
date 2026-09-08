# Changelog

One section per released version, newest first. The release workflow puts
the matching section on the GitHub release.

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
