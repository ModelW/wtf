# Add model-wtf to a project

You have a Model W repository (a `snow.yml` with one image per unit, Django
and/or SvelteKit) and want it under compliance. Plan for one working
session: the agent reviews take minutes each, the human questions
(`!todo`) take as long as finding the answers.

## 1. Install and scaffold

```bash
uv add --dev model-wtf                 # in the repo root, or: pip install model-wtf
uv run model-wtf compliance init       # prompts for the product and the controller
```

`init` writes:

- `compliance/app.yaml` (name, `description: !todo`, controller, processor),
  `compliance/parties/<controller>.yaml` and `<processor>.yaml` with
  `!todo` contact details, a README;
- a `compliance:` block on every image of `snow.yml` (the discovery engine
  guessed from the code) and the per-unit `<unit>/compliance/` folders;
- `.github/workflows/compliance.yml`, the gate on every pull request;
- a managed block in `.github/CODEOWNERS` when `origin` is on GitHub.

It never overwrites anything. Re-run it later to add what is missing.

!!! note "The workflow needs your settings"
    Introspection loads the Django settings (no database is touched). If
    they read environment variables, the workflow needs the same
    placeholder `env:` as your CI's test job. Copy it under `jobs.gate.env`.

## 2. See the to-do list

```bash
uv run model-wtf compliance check
```

Expect: every data item pending review, every touchpoint pending a
declaration, the `!todo` values. Nothing else should be red; a **Tool
error** here means introspection failed (settings, interpreter): fix that
first, the message says what.

## 3. Review the data

```bash
uv run model-wtf compliance data auto-review
uv run model-wtf compliance data list --pending      # must come back empty
```

One agent per model, in parallel (`--workers`, default 16), rounds until
nothing is pending. Each agent reads the model and its write sites and
either confirms the rule's classification or writes an override with a
reason; JSON-like columns get their `contents:` declared. Read what it
wrote under `<unit>/compliance/data/` — the notes cite code, check a few.
Correct with `data override` where it is wrong; the lock remembers the
review commit so the same item is not re-reviewed until its field changes.

## 4. Declare the touchpoints, then group them

```bash
uv run model-wtf compliance touchpoints auto-review
uv run model-wtf compliance activities list
```

Pass 1: one agent per touchpoint reads the view/task/route and declares
the items it handles with the operation (`create`, `read`, `update`,
`delete`, `retention_purge`, `portability`, `consent_withdraw`), the scope
(`subject`, `staff`, `public`, `system`) and the transfers to other
organisations (`party_add` first when the organisation is new). Pass 2:
a single agent groups the PII-touching touchpoints into activities with a
purpose; the legal basis is filled only when evident, the rest is `!todo`.

## 5. Check the flows

```bash
uv run model-wtf compliance flows list --kind transfer
uv run model-wtf compliance flows list --status undeclared
```

Every transfer to another organisation must be declared, with a party that
has a country and a Chapter V safeguard. An `undeclared` flow is data the
code sends somewhere the model does not know: declare it or stop sending.

## 6. Review the threats

```bash
uv run model-wtf compliance threats matrix                 # how many cells are open
uv run model-wtf compliance threats auto-review            # per topic, both units
uv run model-wtf compliance threats findings               # what they found, worst first
```

One agent per security topic (access control, authentication, input,
disclosure, DoS, files, XSS, CSRF, sessions, credentials, surface, stores)
across the touchpoints with open cells, stamping each as mitigated (with
the line that does it), n/a, accepted, or a `!missing` finding. Read the
findings top-down; the real ones become tickets in your tracker, cited by
their `F-` id.

## 7. Commit and open the PR

Commit everything the tool wrote — `snow.yml`, `.github/`, `compliance/`,
`<unit>/compliance/` — and open the pull request. The gate on that first PR
will report everything as *introduced* (the base has no compliance state
yet): that is the bootstrap, merge with that in mind. From the next PR on,
only what changes counts.

## What is left for humans

`check` after the swarms shows three kinds of work:

- **Todo** — facts only a person knows: party addresses and privacy
  emails, an activity's retention, `large_scale`. Edit the YAML.
- **Missing** — established gaps: a right nobody can exercise, a threat
  finding, an undeclared flow. Fix the code or record the decision
  (`accepted` with a reason).
- **Review** — touchpoints the reviewers put back to pending because they
  found a flow the model lacks. Declare the transfer (and the party) or
  refute it.
