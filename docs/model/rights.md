# Rights coverage

Which of the data subject's rights (Art. 15–21) each item can be exercised through, derived from the ops of subject-scoped touchpoints; what cannot be derived is a gap or an exemption note.

Nothing about rights is written on activities. Touchpoints state what the
code does (ops), data items state what is true of the data regardless of
code, activities carry purpose and basis; `check` derives, **per personal
item in every activity that handles it**, whether each right is served
(`src/model_wtf/compliance/rights.py`):

| right | satisfied when | code |
| -- | -- | -- |
| access (Art. 15) | a `subject`-scoped touchpoint `read`s it | `access-missing` |
| rectification (Art. 16) | only for values the person provided: a `subject` `update`, or delete + create (re-creation) | `rectification-missing` |
| erasure (Art. 17) | a `subject` `delete`; `mode: anonymise` needs a ground to keep the row; `legal_obligation` activities exempt by construction | `erasure-missing` |
| storage limitation (Art. 5(1)(e)) | a `retention_purge` covering all rows, or purge cases + a delete path for the rest; a staff/system `delete` also ends the row's life | `retention-missing` |
| portability (Art. 20) | consent/contract, values the person provided, access served: a `portability` op or a JSON API the person calls on their own data | `portability-missing` |
| objection (Art. 21) | legitimate-interests activities: a `subject` update/delete on one of its items (an opt-out) | `objection-missing` |
| consent (Art. 7) | consent activities: `consent.record` created with `consent_for`, and a `consent_withdraw: {for: slug}` op | `consent-proof-missing`, `consent-withdrawal-missing` |
| transfers (Ch. V) | party outside the EEA / adequacy list (`knowledge/adequacy.yaml`) carries `safeguard: sccs|bcr|dpf|derogation` (`dpf` with `dpf_certified: true`); an unknown country is a Todo | `transfer-safeguard-missing` |
| DPIA (Art. 35) | special-category data (`always`) → `dpia_reference` on the activity; confidential data (`large_scale`) only when `app.yaml` says `large_scale: true` | `dpia-missing` |

When a staff screen performs the op but no self-service does, the finding
says so (*no self-service; staff can via admin:people.User — exempt
staff_only if a request process exists*). When every activity holding an
item is about `staff`/`employees`, the back-office is the person's own
interface and staff ops count as the subject's. Transient manual items
(`transient: true`) have no storage-side rights, only transfers. Library
models ship their own rights story (`knowledge/library/*.yaml` `rights:`
block: an audit trail is kept for accountability, a session is purged by the
framework) which applies to inherited columns too (a page type's `owner`).

Exemptions live on the **data item** (`<unit>/compliance/data/<id>.yaml`, or
`<app.Model>.*.yaml` for every personal field of a model; the item's own
file wins right by right):

```yaml
rights:
  erase: {exempt: legal_obligation, note: "accounting records, 10 years"}
  portability: {exempt: derived}
  rectify: {exempt: staff_only}           # verified: an admin op by staff must exist
  access: {exempt: manual, note: "..."}   # always listed under Review
  retention: !missing "no purge task, see FAH-210"
```

Grounds: `legal_obligation`, `contract_active` (still needs an event-driven
`erase`), `not_provided_by_subject` (portability), `derived`
(rectify/portability), `staff_only`, `manual`, `public_interest`, `research`,
`legal_claims`. Precedence for a right: item exemption → derived from ops →
missing. Every unmet right lands in the **Missing** section tagged with its
origin — `[derived]` (the tool), `[claimed]` (an agent that read the code,
via `data_flag` or a `{"missing": ...}` verdict in `activity_create`; the
note is prefixed `[agent]`), `[declared]` (a human's `!missing`) — and
`data why` prints each right's status next to the item's lifecycle.
