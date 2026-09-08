# The gate and the challenger

How a pull request is judged: `check` on both sides, a diff by finding identity, and an agent that reads the change and re-opens the reviews it undermines.

Nobody expects a repository to be clean on day one; the gate expects it to
**not get worse**. `model-wtf compliance ghate` runs the whole `check`
twice — on the base ref, checked out into a temporary `git worktree` with
its own `compliance/` state, and on the head (the working tree by default,
so uncommitted work is gated too) — and fails only on findings the change
**introduces**.

```yaml
# .github/workflows/compliance.yml  (written by `compliance init`)
name: compliance
on: [pull_request]
jobs:
    gate:
        runs-on: ubuntu-latest
        steps:
            - uses: actions/checkout@v4
              with:
                  fetch-depth: 0
                  ref: ${{ github.event.pull_request.head.ref }}
            - uses: ModelW/wtf@v1
              with:
                  openrouter-api-key: ${{ secrets.OPENROUTER_API_KEY }}  # optional
```

The action (`action.yml` at the root of this repository, `v1` tag) installs
uv and model-wtf, runs `uv sync --frozen` / `pnpm install` in every folder
holding a lockfile so introspection works, then runs the gate. Inputs:
`merge-into` (default: the PR base from the event), `fail-on-existing`,
`python-version`, `install-python-deps`, `install-node-deps`. Outputs:
`introduced`, `fixed`, `pre-existing`. Under Actions it emits one
`::error`/`::warning` annotation per introduced finding on the head's
files, a `::notice` verdict, and a Markdown table (introduced / fixed /
pre-existing per check) in the step summary.

Locally:

```
uv run model-wtf compliance ghate --merge-into develop           # gate the working tree
uv run model-wtf compliance ghate --merge-into develop --head feature/x
uv run model-wtf compliance ghate --merge-into develop --format json
```

Findings are compared by **identity** — `(scope, code, subject)`, where the
subject is a data id, a touchpoint id, an activity slug or `file#field`,
never a line number or a message. Folded lines (`12 data item(s) pending`)
are compared item by item, so a PR that adds an unreviewed personal field
fails with exactly that item, while a PR touching an unrelated file when
300 items were already pending passes. Fixed findings are reported too.

The base worktree gets the head's `.venv` / `node_modules` linked in when
the unit's lockfile is byte identical on both sides; otherwise the base
run is approximate and the gate says so (a dependency change is a
legitimate reason for new findings). Exit codes: 0 nothing introduced
(pre-existing findings are listed, not failed), 1 findings introduced, 3
declaration errors in the head (always the PR's fault), 4 tool error;
`--fail-on-existing` also fails on pre-existing findings for repositories
that are already clean.

## The challenger

Fingerprints catch shape changes on data items (a field's type or
nullability); they cannot catch a view that starts mailing an address to a new
provider, a purge task that gets disabled, or a column re-purposed with the
same type. That is a reading job, so with an API key the gate first runs
the **challenger**: an agent with the full git checkout, `git diff` and
`grep`, the `reviews` tool (what reviewers asserted about the changed
files: classifications with their reasons, declared ops, transfers,
exemption notes — every one citing code) and one write tool, `challenge`.
It does not reclassify; it re-opens, with grounds citing the hunk.

`reviews` lists three kinds of assertion: data classifications, touchpoint
declarations and **threat stamps** (`threat api:getOrder#AC01: mitigated —
orders/api.py:283 scoped to request.user`). `challenge` takes any of the
three refs. A hunk that changes what a touchpoint reads, writes, returns or
sends re-opens the declaration; a hunk that removes the control a stamp
cites (a queryset scope, an auth class, a throttle, a validator, a cookie
setting) re-opens that one stamp — `element#SID` — and the cell is stale
(`threats why` shows the grounds) until re-stamped; both when both. A
`!missing` is a finding, not a claim: it cannot be challenged. Stores are
listed when a settings file is in the diff, since their stamps cite
settings.

A challenge is recorded in `data.lock.yaml` (`challenge: {commit,
grounds}`), in the touchpoint manifest, or on the stamp itself, and makes
the item `pending:challenged` (the cell `stale`), which the gate counts as
introduced. The record is
what keeps the non-determinism out of the gate: an item is challenged at
most once per change, a re-review (confirming is fine) moves the challenge
to `answered:` and the same grounds are refused afterwards — a false
positive costs one review, then silence. In CI the challenger's commit is
pushed to the PR branch (`commit-challenges`, default on); the developer
sees exactly which reviews to redo and why. The agent's shell never sees
the CI environment: only the OpenCode whitelist, and our own MCP server
drops `GITHUB_TOKEN` and friends.

```
uv run model-wtf compliance challenge --merge-into develop [--commit]
```
