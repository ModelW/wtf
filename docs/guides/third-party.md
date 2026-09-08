# Add a third-party service

Data leaving the project to another organisation — a geocoder, a payment
provider, an email/SMS service, analytics, an error tracker, a CRM — is a
**transfer**. It needs a party and a declaration on every touchpoint that
sends.

## 1. The party

`compliance/parties/<id>.yaml` (kebab-case id):

```yaml
name: HubSpot, Inc.
country: US
address: 25 First Street, Cambridge, MA 02141, USA
email: privacy@hubspot.com
website: https://www.hubspot.com
hosts: [api.hubapi.com]          # API hostnames the code calls, when they differ from the website
dpa: https://legal.hubspot.com/dpa
safeguard: dpf                   # outside the EEA/adequate countries: dpf | sccs | bcr | derogation
dpf_certified: true              # with dpf: checked on the DPF list
```

`country` decides Chapter V: an adequate country (the EEA, the UK,
Switzerland, Japan…) needs no safeguard; the US needs `dpf` with
`dpf_certified: true`, or `sccs`. A party with a country and no valid
safeguard makes every transfer to it a finding. Address and email may be
`!todo` while you look them up.

The reviewer agents create parties too (`party_add`) when they meet a new
SDK or host, with `!todo` contact details; you complete them.

## 2. The transfer

On each touchpoint that sends, in `<unit>/compliance/touchpoints/<slug>.yaml`:

```yaml
transfers:
  - party: hubspot
    data: [api:people.User.email, api:people.User.phone, api:geo.Address.position]
    purpose: CRM contact for the "customers near you" campaign
```

or through the tools: `touchpoint_set_data` with `transfers` (the agent
does this), `touchpoints set-data` on the CLI.

## 3. What follows automatically

- The flow `api:checkout->party:hubspot` appears in `flows list --kind
  transfer`, with the country and whether it is safeguarded.
- Its disclosure/credential threats are dismissed by the `declared_transfer`
  rule: sending the data there is the intended use. Whether it sends *more*
  than declared is the reviewer's question at declaration time.
- The activity the touchpoint belongs to lists the party under recipients.
- If the code stops calling the host, nothing happens; if it starts calling
  a host no party owns, `flow-undeclared`.

## Not a third party: a service the project runs

Do not invent a party for the project's own realtime server, search index
or the SMTP relay behind `EMAIL_HOST` — a party is a named organisation. Those
are **stores**: declare one in `<unit>/compliance/stores/<slug>.yaml`

```yaml
type: realtime          # or external, search, ...
backend: hocuspocus
name: TMW kitchen board
hosts: [TMW_URL]        # the setting name or hostname the code reaches it by
```

(or `store_add` from the agent) and put the copy on the touchpoint:

```yaml
stores:
  - store: tmw
    data: [api:orders.Order.reference, api:orders.Order.status]
    purpose: live kitchen board
```

The flow `api:task:kitchen.sync_order_to_board->api:tmw` is a store flow
with the store's threat cells; nothing enters the recipients column. When
the operator is a deployment fact (the SMTP relay), `type: external` and
`provider: !todo` for a human.

## Hosts and the project's own

The introspection reads the hostnames in the view's URL literals and
well-known SDK client names. Hosts from `ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS`,
`CORS_ALLOWED_ORIGINS` and any `*_URL` setting are the project's own, as
are docker service names and loopback. A `settings.X_URL` / `X_HOST` the
view reads is reported as `setting:X_URL`. Everything else must belong to a
party (its `website` domain or `hosts` list) or to a store (`hosts`, which
may name the setting).
