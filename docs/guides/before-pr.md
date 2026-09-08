# Before opening a pull request

Run what the gate will run, on your working tree, before you push:

```bash
uv run model-wtf compliance ghate --merge-into develop
```

It checks out the base into a temporary worktree, runs `check` on both
sides and prints three lists: **introduced** (yours to fix), **fixed**
(findings your change closed), **pre-existing** (not yours). Exit 0 when
nothing is introduced, even if the repo has open findings of its own.

With `OPENROUTER_API_KEY` in the environment it also runs the challenger:
an agent that reads your diff and re-opens the declarations and threat
stamps it undermines. Each re-opening becomes an introduced line. Without
the key, `--no-challenge` is implied and you get the deterministic part
only — that is what the gate in CI adds on top.

## The usual outcomes

- **You changed a model.** A new or changed field is a pending data item:
  `data auto-review --unit <unit>` or `data reviewed`, and check its
  rights lines.
- **You added a route or a task.** It has no manifest: `touchpoints
  auto-review --unit <unit>`, then `threats auto-review --elements <id>`
  so its threat cells are looked at.
- **You touched a view the model has an opinion on.** The challenger may
  re-open its declaration or one of its stamps; `touchpoints show` and
  `threats why` print the grounds. Re-declare or re-stamp, confirming when
  it still holds.
- **You call a new host.** Declare the party and the transfer, or the
  gate reports an undeclared flow.

## Commit the answers with the code

The decision files live next to the code and travel with the PR. A review
that answers a challenge records `answered:` so it is not raised twice;
the challenger in CI, when it re-opens something, commits its `challenge:`
blocks onto your branch (`commit-challenges`, on by default) so you see
exactly what to redo.
