# Flows

Where the data goes: one edge per movement, with a kind and a status. The fourth inventory, and the one that keeps the threat reviewers from calling a declared transfer a leak.

Data, touchpoints and activities say what exists, who touches it and why.
**Flows** say where it goes: one per edge along which items move, named
`source->sink`, with a **kind** decided from its ends and a **status**:

| kind       | ends                                  | status                    |
|------------|---------------------------------------|---------------------------|
| `request`  | an actor and a touchpoint             | derived (shapes)          |
| `store`    | a touchpoint and a project store      | declared (ops)            |
| `transfer` | a touchpoint and a party              | declared (`transfers`)    |
| `call`     | a front route and an API operation    | derived (introspection)   |
| `defer`    | a touchpoint and a background task    | derived                   |
| any        | found by a reviewer, absent from the model | **undeclared** — a gap |

```
uv run model-wtf compliance flows list [--unit api] [--element api:listRestaurants] [--kind transfer] [--status undeclared] [--format json]
uv run model-wtf compliance flows show api:listRestaurants->party:mapbox   # items, and the threat cells on it
```

The threat reviewers get the same inventory in words through the `flows`
tool (and inside `threat_topic`): *sends geo.Address.position to
party:mapbox (US) — declared transfer, safeguarded: sending it there is the
intended use*; *create/read Cart rows on api:db-default*; *exchanges 38
items with anonymous callers*. A declared, safeguarded transfer is not a
leak, and the reviewer no longer reconstructs the flows from the code and
calls one. What the code sends somewhere **not on the list** is reported
with `flow_report(element, sink, data, note)`: the manifest gets an
`undeclared:` entry, `check` shows a `flow-undeclared` finding (Missing) and
the touchpoint is pending again — the declaration is incomplete. Declaring
the transfer (party first) closes it; the transfer's own threats then
follow the `declared_transfer` rule.

Flow-only threats (DS06, DR01, AC22…) are stamped per flow: `DS06@actor:public`
for the response, `DS06@api:db-default` for the store side. A bare `DS06` on
the touchpoint is refused while several flows carry the open cell, with the
keys to use; it is accepted when only one does.
