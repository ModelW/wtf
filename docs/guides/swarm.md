# Run the reviewer swarm

Three reviews are done by agents: data classification, touchpoint
declarations (+ grouping into activities), threat stamps. All three run
through OpenCode with the model-wtf MCP server as their only way to write.

```bash
uv run model-wtf compliance data auto-review        [--unit api] [--workers 16] [--max-rounds 20]
uv run model-wtf compliance touchpoints auto-review [--unit api] [--group-only | --no-group]
uv run model-wtf compliance threats auto-review     [--unit api] [--by topic|touchpoint] [--elements a,b]
```

## What a run looks like

Rounds: each round dispatches the pending items to `--workers` parallel
sessions in batches; what a session wrote is on disk before the next round
computes what is still pending. The command exits 0 when nothing is
pending, 3 (`FINDINGS`) when items remain after `--max-rounds` — re-run to
resume, nothing is redone. Ctrl-C is safe: stamps and lock entries are
written per item under a lock.

The narration is one line per decision, with the id and the evidence:

```
  ✓ api:listRestaurants LB01 (API Manipulation) mitigated  api.py:44-45 response contracted by RestaurantListSchema…
  - api:getRestaurant DE02 (Double Encoding) n/a  the endpoint never decodes strings itself…
  ! F-0060 api:listRestaurants AC09 (Functionality Misuse) missing  api.py:104-108 — an anonymous caller with any address UUID…
```

## Threats: per topic

The default `--by topic` gives one agent one security question across many
touchpoints (with the topic's checklist and each touchpoint's open cells,
code location, auth and **flows**); `--by touchpoint` gives one agent all
the questions on one touchpoint. Measured on FAH, per topic completed in a
third of the tokens and found the ownership gaps the other missed. Stamps
carry `by: agent`; a `!missing` written by an agent is prefixed `[agent]`.

## Model and cost

`--model provider/model` (default `openrouter/openrouter/auto`); `--max-tokens` stops starting new rounds past a budget. The
summary prints tokens, cost and the models actually used. Prompts are
short on purpose: small models answer one narrow question well and fifteen
badly.

## What the agents cannot do

Everything else. The sandbox denies every tool but the read tools and the
one or two model-wtf writes the role needs (`review_model`,
`touchpoint_set_data`, `threat_stamp`, `flow_report`, `party_add`…). Their
output is validated by the same schemas and rules as a human's, and the
challenger later doubts it like any other review. CI secrets never reach
the agent's environment.
