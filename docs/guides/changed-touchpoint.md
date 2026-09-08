# I changed a touchpoint

A touchpoint's declaration says what it does to which data, for whom, and
what it sends elsewhere; its threat stamps say which controls are in place.
Both rest on the code as it was when reviewed. When you change the code,
two mechanisms re-open what your change may have invalidated:

- **Fingerprints** on data items: a field's type, nullability or relation
  changed re-pends the item's review.
- **The challenger** on declarations and stamps: it reads the diff of your
  PR, the declarations and stamps that cite the changed files (`reviews`
  lists them with their reasons and code citations), and `challenge`s each
  one a hunk plausibly undermines, with the hunk as grounds.

```bash
uv run model-wtf compliance touchpoints show api:setFavoriteAddress
```

shows the facts introspection sees now (auth, request/response shapes,
calls, hosts), the current declaration, and any open `CHALLENGED:` with
its grounds.

## Re-declare

```bash
uv run model-wtf compliance touchpoints auto-review --unit api           # every pending one
uv run model-wtf compliance touchpoints set-data api:setFavoriteAddress "geo.Address.*=read,update" --note "geo/api.py:320"
```

Confirming the previous declaration is a valid answer: the challenge moves
to `answered:` and the same grounds are refused afterwards. The manifest
keeps its threat stamps across a re-declaration.

## Re-stamp

```bash
uv run model-wtf compliance threats why api:setFavoriteAddress
uv run model-wtf compliance threats stamp api:setFavoriteAddress AC01 --status mitigated --note "geo/api.py:320 user.addresses.filter(pk=...)"
```

A challenged stamp is **stale**: counted open, listed with the grounds.
Re-stamping answers it. If the control really is gone, do not re-stamp:
fix the code, or record the finding (`--missing "…"`).

## New flows

If your change makes the touchpoint send data somewhere new — a third-party
API, an email provider, a webhook — declare the transfer on the touchpoint
and the party under `compliance/parties/` (see [Add a third-party
service](third-party.md)). The introspection sees hosts in the view's URL
literals; one that no party owns is an `undeclared` flow and a finding on
its own.
