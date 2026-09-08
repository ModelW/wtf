# Activities and legal bases

Groups of touchpoints that serve one purpose — the rows of the Art. 30 register — with their legal basis, retention and the data they derive from their touchpoints.

```
uv run model-wtf compliance activities list [--format json]
uv run model-wtf compliance activities explain <slug>
uv run model-wtf compliance activities create <slug> [--name] [--purpose] [--legal-basis] [--touchpoint unit:id]... [--subject]... [--recipient]... [--retention]
uv run model-wtf compliance activities add <slug> <unit:id>...
uv run model-wtf compliance data why <unit:id>... [--model unit:app.Model] [--manifests] [--format json]
```

`compliance/activities/<slug>.yaml` (repository root, activities span units)
is the Art. 30 row: `name`, `purpose`, `legal_basis` (`consent | contract |
legal_obligation | vital_interests | public_task | legitimate_interests`, or
`no_pii` — a claim that the activity handles no personal item, verified at
every check: `no-pii-violated` otherwise), `data_subjects`, `touchpoints`,
`recipients` (party ids), `controller`/`processor` (default: `app.yaml`'s);
`consent: {record: <ref>, granularity: separate|bundled}` for consent-based
ones (the stored proof, created with `create: {consent_for: <slug>}`),
`interest` for legitimate interests (the balancing test), `basis_note` when
two bases compete, `dpia_reference` when the derived trigger fires. Any of
them may be `!todo` or `!missing "why"`. Everything else is **derived** from
the touchpoints: the data items, hence categories, stores, maximum
sensitivity, DPIA trigger, units, recipients and the ops per item. Retention
is not a field: the policy is the `retention_purge` op in the code.
