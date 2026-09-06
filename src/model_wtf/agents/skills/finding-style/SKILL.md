---
name: finding-style
description: How to write a finding a developer will act on in under a minute.
---

# Finding style

A finding is a PR comment. Write it for the developer who will fix it.

- **summary**: one line, active voice, names the element:
  "Unauthenticated POST creating Lead rows with no rate limiting."
- **detail**: what you saw, where (`path:line`), why it fails the rule.
  Two to five sentences. No general security lectures.
- **remediation**: the concrete change, ideally with the exact setting,
  decorator or call: "Add `throttle=AnonRateThrottle('10/m')` to the
  router or require `auth=django_auth`". Offer the accept path when a
  public endpoint is legitimate: "if intentional, document the edge rate
  limit as an assumption and accept".
- **references**: reuse the rule's references; add a CWE/CAPEC only if
  it is the exact match.
- **provenance**: at least one `path:line`; the first one anchors the PR
  comment.
- **severity**: the rule's, unless the context is clearly worse (special
  categories, credentials, public admin) -- then raise it and say why in
  detail. Never lower it.

Do not report style nits, hypothetical future risks, or issues outside
the checkpoint you were given. One checkpoint, one finding.
