# My PR failed the gate

The `compliance` check on your pull request is red. The gate compares the
compliance state of your branch with its base and fails **only on what your
change introduced**; the summary reads like:

```
compliance gate: 4 introduced, 0 fixed, 195 pre-existing
```

The 195 are not yours. The 4 are, and each has a line in the job summary
(and as an annotation on the file) telling you what and where.

## Reproduce locally

```bash
uv run model-wtf compliance ghate --merge-into develop
```

Same comparison, same output, on your working tree (uncommitted changes
included). Add `--no-challenge` to skip the agent and see only the
deterministic part.

## The kinds of line and what to do

### `pending-review` — a new data item

```
api:people.User.date_of_birth: 1 data item(s) pending (1 new)
```

You added or changed a model field. Review it:

```bash
uv run model-wtf compliance data auto-review --unit api
# or by hand:
uv run model-wtf compliance data reviewed api:people.User.date_of_birth --note "birthday campaign, personal/identity"
```

If the rule's classification is wrong, `data override` with the right one
and a reason. Rights lines (`#access`, `#erase`, …) on the same item follow:
the item needs a subject-scoped touchpoint that reads / deletes it, or an
exemption note.

### `touchpoint-pending` — a declaration re-opened

```
api:setFavoriteAddress: 1 touchpoint(s) pending
```

Either a new route/task with no manifest yet, or the challenger cast a
doubt on an existing declaration (`challenge:` block in the manifest, with
the hunk and the grounds). Re-declare:

```bash
uv run model-wtf compliance touchpoints show api:setFavoriteAddress     # facts + the challenge
uv run model-wtf compliance touchpoints auto-review --unit api           # or set-data by hand
```

A re-declaration that confirms the previous one is a fine answer; it moves
the challenge to `answered:` and the same grounds are not raised again.

### `threat-open` — a stamp re-opened

```
api:setFavoriteAddress#AC01: ... (1 stamp(s) challenged)
```

The challenger read your hunk and found it removes or weakens the control a
threat stamp cites. `threats why` shows the grounds and the old note:

```bash
uv run model-wtf compliance threats why api:setFavoriteAddress AC01
```

Either the control is still there (re-stamp `mitigated` with the line that
does it now), the threat no longer applies (`n/a`), you accept the risk
(`accepted`, say why) — or you just introduced the bug; fix it, then
re-stamp.

```bash
uv run model-wtf compliance threats stamp api:setFavoriteAddress AC01 --status mitigated --note "geo/api.py:320 scoped to user.addresses"
```

### `flow-undeclared` — data going somewhere new

```
api:checkout->api.hubapi.com: api:checkout sends ... to api.hubapi.com, which the manifest does not declare
```

Your code calls a host no party owns. If it is meant to: declare the party
(`compliance/parties/hubspot.yaml`: name, country, website, `hosts`, and a
Chapter V safeguard when outside the EEA) and add the transfer to the
touchpoint's `transfers:`. If it is the project's own host, add it to the
settings the introspection reads (`ALLOWED_HOSTS`, a `*_URL`). If it is
not meant to, remove the call.

### `missing` — a rights gap, `todo` — a question

Introduced when your change made an item lose the touchpoint that served a
right (a deleted endpoint), or added a party or activity with `!todo`
fields. Answer the question or restore the path.

## When the challenger is wrong

It re-opens, it does not decide. A false positive costs one re-review: the
answer is recorded, the same grounds are refused afterwards. If it keeps
being wrong on the same class of change, that is a tool issue — say so.
