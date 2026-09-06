---
name: data-items
description: The data-item vocabulary and the "contents, not schema" rule for opaque fields.
---

# Data items

Every field/content is tagged with exactly one **item** from this
vocabulary. The union of items over a data object gives the Art. 30(1)(c)
categories of personal data AND the threat model's data classification.

| item | what it covers | Art. 9 | DPIA trigger |
| --- | --- | --- | --- |
| `email` | any e-mail address reaching a person | | |
| `name` | first/last/display/full name | | |
| `phone` | fixed or mobile numbers | | |
| `address` | postal address parts | | |
| `identifier` | ids assigned to a person: customer id, VAT no., SSN, IP, plate | | |
| `financial` | IBAN, cards, amounts, invoices, salary, scoring | | |
| `health` | physical/mental health, care, disability | **yes** | yes |
| `identity_document` | passport / ID scans and numbers | | yes |
| `biometric` | fingerprints, face geometry, voice prints | **yes** | yes |
| `location` | GPS, geolocation traces | | yes |
| `behavioural` | browsing, clicks, analytics, preferences, scoring | | yes |
| `free_text` | anything a person typed; may hold any other item, about third parties | | |
| `credential` | passwords, hashes, API keys, tokens, TOTP seeds (not PII) | | |
| `none` | examined, not personal data (UTM, SKU, feature flag) | | |

## Contents, not schema

PII very often lives inside JSON/blob/text fields. Declare **what** a
field holds, not **where**:

```yaml
fields:
  email: {item: email}                      # scalar shorthand
  form_data:                                # JSONField
    contents:
      - {name: first_name, item: name}
      - {name: iban, item: financial}
      - {name: utm_campaign, item: none}    # looked, not personal data
      - {name: free_comment, item: free_text, multi_subject: true}
    unknown_contents: possible              # none | possible | likely
```

- The same information at three JSON paths is **one** content.
- `unknown_contents: likely` when callers can store arbitrary payloads
  (webhook bodies, `request.data` dumped as-is). It forces tight retention
  and forbids any "complete erasure" claim.
- Prefer the most specific item: an IBAN is `financial`, not `identifier`.
- A field you could not resolve is NOT `none`; leave it out of `contents`
  and raise `unknown_contents`.
