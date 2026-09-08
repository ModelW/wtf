# Read the register (DPO / CISO)

You own the decision files — `CODEOWNERS` routes every change to
`compliance/` through you — and you need the picture, not the tool. Every
command below is read-only.

## The state in one screen

```bash
uv run model-wtf compliance check
uv run model-wtf compliance check --todo        # only the questions waiting for a person
```

`check` is grouped by what has to happen next: **Errors** (declarations
that do not parse), **Missing** (established gaps: a right nobody can
exercise, a threat finding, an undeclared transfer), **Todo** (facts only a
person knows), **Review** (agents or developers have work), **Info**. The
exit code follows the sections; the JSON form (`--format json`) has every
line with its file, subject and origin (`claimed` by a reviewer, `declared`
by the code, `library` default).

## The register of processing activities (Art. 30)

```bash
uv run model-wtf compliance activities list
uv run model-wtf compliance activities explain <slug>
```

One activity per purpose. `explain` shows its touchpoints (the routes,
tasks and screens that serve it), the data items derived from them with
their categories and the highest sensitivity, the legal basis (with the
consent block when it is consent), retention, recipients, and the DPIA
question: `always` for special categories, `large_scale` when `app.yaml`
says the product is, `never` otherwise. Anything the tool could not derive
is `!todo` in the activity file — that is where your answers go.

## What data, where, who touches it

```bash
uv run model-wtf compliance data list                 # every item, classification, store
uv run model-wtf compliance data why api:orders.Order.delivery_address
uv run model-wtf compliance stores list
uv run model-wtf compliance flows list --kind transfer
```

`data why` names the touchpoints handling an item and the activities they
belong to; `flows list --kind transfer` is the list of transfers to other
organisations, each with the party, its country and whether Chapter V is
satisfied (adequate country, DPF-certified, SCCs…). The party files under
`compliance/parties/` are the contact details you will put in a notice.

## Rights coverage

```bash
uv run model-wtf compliance check | grep -A30 Missing
```

A right (access, rectification, erasure, restriction, portability,
objection) is *covered* for an item when a subject-scoped touchpoint
performs the matching operation on it, or when a note explains the
exemption (`no self-service; staff can via …`, `audit trail kept for
accountability`). What is neither is a Missing line naming the item and the
right.

## The threat model

```bash
uv run model-wtf compliance threats findings                        # worst first
uv run model-wtf compliance threats findings --min-severity high
uv run model-wtf compliance threats why F-0042
```

Every finding has a stable id, an effect (disclosure, tampering,
destruction, denial, escalation, repudiation), a degree (one attribute, one
record, bulk), the actors who can reach it (anonymous, subject, staff,
system), the data it touches and a severity bucket from impact × likelihood.
`why` gives the evidence the reviewer cited and the flow that carries the
weight. Findings are what becomes tickets; `accepted` stamps with a reason
are risk decisions and are listed too.

## What you are asked to decide

- The `!todo` values: contact details, `description`, `large_scale`,
  retention periods, legal bases the tool could not tell.
- Undeclared flows the reviewers found (`flows list --status undeclared`):
  a transfer to declare, with its party, or code to remove.
- Accepted risks: a `!missing` you decide to live with becomes a stamp
  `accepted` with the reason, by you.
