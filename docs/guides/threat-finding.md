# Answer a threat finding

A finding is a `!missing` stamp: a reviewer (agent or human) looked at a
threat on an element and found the control absent. It has an id, a
severity, and evidence citing code.

## Read it

```bash
uv run model-wtf compliance threats findings
uv run model-wtf compliance threats why F-0042
uv run model-wtf compliance threats why api:getOrder AC01        # same, by element and SID
```

`why` prints, for the element, every threat with its verdict: `never`
(impossible in this stack, and why), `dismissed` (the rule that closed it),
`stamped` (status and note), `stale` (the stamp's code moved or a challenger
doubted it, with the grounds), `missing` (the finding: evidence, effect,
degree, actors, data, severity). Flow-keyed entries (`DS06@party:mapbox`)
are about that one flow.

## Decide

Four honest answers, one command:

| The situation | Stamp |
|---|---|
| The control exists, the reviewer missed it | `--status mitigated --note "file.py:123 what does it"` |
| The threat cannot happen on this element | `--status n/a --note "why"` |
| You accept the risk | `--status accepted --note "why, who decided"` |
| It is a real gap | leave it; fix the code, then re-review |

```bash
uv run model-wtf compliance threats stamp api:getOrder AC01 --status mitigated --note "orders/api.py:283 queryset scoped to request.user"
```

`mitigated` needs a `file:line`; `accepted` and `n/a` need a reason. The
stamp records the commit and the element's fingerprint: when the code
behind it moves, the cell goes **stale** and comes back for review.

## Narrow the weight, not the evidence

The severity is computed from facts (who can reach the touchpoint, what
data it handles, how much of it). A reviewer may narrow it when the facts
overstate: `--effect`, `--degree`, `--actor` on a `--missing` stamp. The
narrowing is kept separately and re-applied when the matrix is rebuilt,
so a code change that widens the reach shows through.

## Flow threats

Disclosure and credential threats (`DS06`, `DR01`, `AC22`…) live on flows:
the response to the caller, the write to a store, the transfer to a party.
A finding names the flow (`api:checkout → actor:public`); stamp the same
key: `threats stamp api:checkout DS06@actor:public …`. A `mitigated` or
`n/a` on the bare `DS06` covers every flow of the element; a `!missing`
must name one.

## When it was a false positive

Say so in the stamp (`n/a` or `mitigated`, with the line). If the same
class of false positive recurs — a framework view, a pattern the rules
should know — that is a tool issue, not something to keep stamping.
