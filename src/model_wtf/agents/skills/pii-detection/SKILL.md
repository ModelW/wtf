---
name: pii-detection
description: Where personal data hides in Model W projects (field survey patterns).
---

# Finding the PII the schema does not show

Patterns seen across seven Model W projects:

1. **JSON blobs**: `form_data`, `payload`, `metadata`, `extra`, `answers`,
   `raw_response`. Open the serializers, forms, admin, fixtures and tests
   that write them; list the keys as `candidate_contents`.
2. **Shadow stores**: the same person copied into a CRM sync table, a
   search index document, a denormalised `*_cache` column, an
   `EmailLog.context`, a task payload (`procrastinate_jobs.args`,
   Celery result backend), an audit/history table
   (`django-simple-history`, `auditlog`).
3. **Files**: `FileField`/`ImageField` -> scans, signed PDFs, exports.
   Object storage keeps them after row deletion unless code removes them.
4. **Capability tokens**: signed URLs, magic links, invite tokens are
   `credential`; the row they point to identifies a person.
5. **Free text everywhere**: comments, notes, chat, support tickets,
   `description` fields users fill. Always `free_text`, often
   `multi_subject: true`.
6. **Logs and observability**: `logger.info(request.data)`, Sentry with
   `send_default_pii=True`, analytics events carrying emails. These are
   recipients (sinks) with retention, and MW-SEC-005 material.
7. **Config**: `ADMINS`, hard-coded emails in settings, seed fixtures with
   real-looking people.
8. **Identifiers that look technical**: IP addresses, device ids, cookie
   ids, Stripe customer ids are `identifier` (they single out a person).

When in doubt whether a field is personal data, it is; use the closest
item and explain in `rationale`.
