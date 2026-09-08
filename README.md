# model-wtf

Compliance as code for [Model W](https://github.com/ModelW) projects.

## Why

A GDPR register, a rights matrix and a threat model are descriptions of
what the code does. Written by hand they are wrong the week after; written
once, they never meet the pull request that breaks them.

`model-wtf` derives them from the repository instead. It introspects the
application (Django models and URL confs, task registries, SvelteKit
routes) into inventories — data items, the touchpoints that handle them,
where the data flows, the stores it lives in — and lets humans or agents
record the judgements the code cannot carry (is this field personal? does
this endpoint serve the subject or the staff? is that threat mitigated?)
as small YAML files next to the code. Everything downstream — the Art. 30
register, rights coverage, the weighed findings — is computed from that.
A **gate** runs on every pull request and fails the change that introduces
a gap; a **challenger** agent reads the diff and re-opens the reviews it
undermines. The to-do list is, at all times, exactly the distance between
the code and its declarations.

## How

In the root of a Model W repository (a `snow.yml`, or a `.model-wtf.yml`),
with an [OpenRouter](https://openrouter.ai) key in `OPENROUTER_API_KEY`:

```bash
uvx model-wtf compliance init                     # compliance/ folders, snow.yml blocks, CODEOWNERS, CI workflow
uvx model-wtf compliance data auto-review         # agents classify every field, model by model
uvx model-wtf compliance touchpoints auto-review  # and declare what each route / task / screen does
uvx model-wtf compliance activities list          # the register of processing activities, from the code
uvx model-wtf compliance check                    # what is still open — and the gate on your next PR
```

Nothing is overwritten, what the agents cannot know is left as `!todo`
for a human, and every file they wrote is reviewable in the diff. Without
an API key the same commands work by hand (`data review`, `touchpoints
set-data`, `threats stamp`).

## Learn more

**<https://modelw.github.io/wtf/>**

- [The cycle](https://modelw.github.io/wtf/model/cycle/) — the model in
  one page: data, touchpoints, flows, activities, threats, the gate.
- [Add model-wtf to a project](https://modelw.github.io/wtf/guides/add-to-project/)
  · [My PR failed the gate](https://modelw.github.io/wtf/guides/pr-failed/)
  · [Answer a threat finding](https://modelw.github.io/wtf/guides/threat-finding/)
  · [Add a third-party service](https://modelw.github.io/wtf/guides/third-party/)
  · [Run the reviewer swarm](https://modelw.github.io/wtf/guides/swarm/)
  · [Read the register](https://modelw.github.io/wtf/guides/dpo/)
- Reference: [CLI](https://modelw.github.io/wtf/reference/cli/)
  · [MCP tools](https://modelw.github.io/wtf/reference/mcp/)
  · [file schemas](https://modelw.github.io/wtf/reference/schemas/)
  · [threat catalogue](https://modelw.github.io/wtf/reference/threats/)

## Misc

- Install for good: `uv add --dev model-wtf`, then `uv run model-wtf …`.
- The gate in CI: `uses: ModelW/wtf@v1` (see
  [action.yml](action.yml); `init` writes the workflow).
- Contributing and releasing: [docs/contributing.md](docs/contributing.md).
- Changes: [CHANGELOG.md](CHANGELOG.md). License: MIT.
