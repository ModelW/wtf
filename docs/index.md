# model-wtf

Compliance as code for Model W projects. The tool reads a repository, builds
an inventory of what the application does with personal data — the data
items, the entry points that touch them, where the data goes, the
processing activities — and a threat model on top of it. Every judgement a
human or an agent makes is written next to the code as a small YAML file
and checked on every pull request: the **gate** fails a change that
introduces a gap, and a **challenger** agent re-opens the reviews a change
undermines.

The result is a register of processing activities (GDPR Art. 30), a rights
coverage matrix, a threat model with weighed findings, and a to-do list
that is exactly the distance between the code and the declarations.

```bash
uv add --dev model-wtf          # or: pip install model-wtf
uv run model-wtf compliance init
uv run model-wtf compliance check
```

## Where to go

<div class="grid cards" markdown>

- **I want to understand the model**

    What a data item, a touchpoint, a flow, an activity, a threat cell are,
    and how they fit. Start with [The cycle](model/cycle.md).

- **I am adding it to a project**

    [Add model-wtf to a project](guides/add-to-project.md): `init`, the
    first reviews, the workflow.

- **My PR failed the gate**

    [My PR failed the gate](guides/pr-failed.md): reading the lines,
    what to do for each kind.

- **I am the DPO / CISO**

    [Read the register](guides/dpo.md) and
    [Answer a threat finding](guides/threat-finding.md).

</div>

## Principles

- **Facts from the code, decisions in files.** Introspection produces the
  facts (models, routes, schemas, auth, calls); nothing is guessed from
  names alone. Every decision — a classification, a declaration, a stamp —
  is a YAML file under version control, with who made it and why.
- **Deterministic first, agents second.** Whatever can be decided from a
  fact is decided by a rule; agents get the questions that need reading,
  one narrow question at a time, with one write tool each. Their output is
  checked by the same rules as a human's.
- **Nothing silent.** Unknown keys are errors. A value nobody knows is
  `!todo`, an established gap is `!missing`; both show up in `check` until
  someone answers.
- **The gate is a diff.** A pull request is compared to its base by finding
  identity; it fails only on what it introduces. Pre-existing findings are
  listed, never blocking.
