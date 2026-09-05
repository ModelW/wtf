"""A minimal valid ``compliance/`` tree, shared by the declaration tests.

Everything references everything: the activity points at the actor, the
recipient and (through its ``.gen``) the data object; the data object
points at the actor. Tests derive broken variants by overriding one file.
"""

from __future__ import annotations

CONTROLLER = """
name: ACME SAS
contact:
  address: 1 rue de la Paix, 75002 Paris
  email: privacy@acme.example
dpo:
  name: Jane DPO
  contact:
    address: same
    email: dpo@acme.example
"""

SECURITY = """
general_description: |
  TLS everywhere, SSO with mandatory 2FA, encrypted backups.
"""

ACTOR_CUSTOMERS = """
name: Customers
description: People who bought something.
"""

ASSUMPTION_EDGE = """
summary: Rate limiting is enforced at the DigitalOcean edge.
review_by: 2027-03-01
"""

RECIPIENT_STRIPE = """
name: Stripe Payments Europe Ltd
kind: processor
dpa_reference: contracts/stripe-dpa-2024.pdf
third_country: US
transfer_safeguards: EU-US Data Privacy Framework
"""

ACTIVITY_BILLING = """
purpose: Issue and archive invoices for purchased services.
lawful_basis: legal_obligation
data_subject_categories: [customers]
recipients: [stripe]
"""

ACTIVITY_BILLING_GEN = """
by: extractor
members: [http:POST:/back/api/invoices/]
data_objects:
  billing.invoices: [read, write]
suggested_recipients: [stripe]
"""

DATA_INVOICES = """
drafted_by: agent
name: Your invoices
description: Invoices issued for your purchases.
fields:
  customer_name: {item: name}
  amount: {item: financial}
  billing_data:
    contents:
      - {name: address, item: address}
      - {name: iban, item: financial}
      - {name: utm_campaign, item: none}
    unknown_contents: possible
subject_categories: [customers]
identification: identified
rectification: dpo
retention:
  - time_limit: P10Y
    trigger: invoice_issuance
    statutory_basis: French Commercial Code Art. L123-22
    expiry_action: delete
"""

LEDGER_POST_INVOICES = """
MW-SEC-001:
  status: not_ok
  finding: F-0001
  evaluated: {sha: 3f9c1a2, model: test, at: 2026-09-05T13:02:00Z}
  depends_on: [apps/billing/api.py]
GDPR-RETENTION-ENFORCED:
  status: ok
  evidence: purge task scheduled daily
INP03: {status: n_a, reason: "profile django: no SSI"}
"""

FINDING_0001 = """
checkpoint: MW-SEC-001@http:POST:/back/api/invoices/
severity: high
summary: Unauthenticated POST creating invoices.
detail: apps/billing/api.py:14 has auth=None.
remediation: Require authentication.
references: [CAPEC-212]
provenance: [apps/billing/api.py:14]
evaluated: {sha: 3f9c1a2, model: test, at: 2026-09-05T13:02:00Z}
accepted:
  justification: public form, rate limited at the edge
  assumption: edge-rate-limit
  review_by: 2027-03-01
"""

SNOW_ONE_UNIT = """
images:
  - id: api
    context: api
    compliance: compliance
"""


def valid_tree(prefix: str = "api/compliance") -> dict[str, str]:
    """The minimal valid tree, every file under ``prefix``."""
    return {
        f"{prefix}/controller.yaml": CONTROLLER,
        f"{prefix}/security.yaml": SECURITY,
        f"{prefix}/actors/customers.yaml": ACTOR_CUSTOMERS,
        f"{prefix}/assumptions/edge-rate-limit.yaml": ASSUMPTION_EDGE,
        f"{prefix}/recipients/stripe.yaml": RECIPIENT_STRIPE,
        f"{prefix}/processing/billing.yaml": ACTIVITY_BILLING,
        f"{prefix}/processing/billing.gen.yaml": ACTIVITY_BILLING_GEN,
        f"{prefix}/data/billing.invoices.yaml": DATA_INVOICES,
        f"{prefix}/elements/http.POST.back.api.invoices.yaml": LEDGER_POST_INVOICES,
        f"{prefix}/findings/F-0001.yaml": FINDING_0001,
    }
