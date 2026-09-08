# The challenger re-opened my review

The gate on your PR shows a line like

```
api:setFavoriteAddress#AC01: … (1 stamp(s) challenged)
api:checkout: 1 touchpoint(s) pending
```

and your branch has a new commit from the workflow, touching a
`compliance/` file: a `challenge:` block with a commit, a timestamp and one
line of **grounds** — the hunk and the assertion it undermines.

## What a challenge is

The challenger is an agent with the full checkout, `git diff` and `grep`,
one read tool (`reviews`: what reviewers asserted about the changed files,
each assertion citing code) and one write tool (`challenge`). It does not
reclassify or re-stamp anything. It says *"this claim rested on that line,
and that line changed"*, and the claim goes back to pending until someone
looks. That is the whole mechanism by which a code change re-validates the
compliance and threat model attached to it.

Three kinds of ref:

| Ref | Re-opens |
|---|---|
| `api:shop.Customer.email` | a data item's classification (`data.lock.yaml`) |
| `api:checkout` | a touchpoint's declaration (its manifest) |
| `api:checkout#AC01`, `api:checkout#DS06@party:mapbox` | one threat stamp |

## Answer it

Read the grounds (`touchpoints show`, `threats why`, or the YAML), then:

- **it still holds** — re-declare / re-stamp with the same content and the
  line that shows it. The challenge moves to `answered:`; the same grounds
  are refused for this change.
- **it no longer holds** — declare what is true now (the new item, the new
  transfer, the wider scope) or record the finding (`--missing`).
- **you introduced a bug** — fix it, then re-stamp.

## Limits

At most one challenge per ref per change; already answered grounds are
refused; a `!missing` cannot be challenged (a finding is not a claim). A
false positive costs one confirmation. The deterministic checks — new
fields, new hosts, dropped auth wrappers — do not depend on it.
