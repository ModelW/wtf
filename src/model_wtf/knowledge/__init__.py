"""Knowledge: the rules, vocabulary and catalogues model-wtf ships with.

Knowledge is data, not code. Every rule, data item and egress entry is a
small YAML file under this package so that a security engineer can review
a change to a rule the way they review any other diff. The Python side
only knows how to load and validate those files
(:mod:`model_wtf.knowledge.loader`) and what shape they have
(:mod:`model_wtf.knowledge.schemas`).

Layout::

    knowledge/
    ├── frameworks/*.yaml     # gdpr, stride: names + descriptions
    ├── data_items/*.yaml     # the vocabulary ``item:`` values come from
    ├── egress/*.yaml         # known third parties (Sentry, Stripe, ...)
    └── rules/
        ├── security/*.yaml   # MW-SEC-*
        └── gdpr/*.yaml       # GDPR-*
"""

KNOWLEDGE_VERSION = 1
"""Bumped when the rule set changes in a way that should re-stage checkpoints."""
