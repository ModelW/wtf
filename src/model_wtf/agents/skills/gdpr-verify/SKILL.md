---
name: gdpr-verify
description: What each GDPR verify rule means concretely in Django / Model W code, and what counts as evidence.
---

# Verifying GDPR rules against code

Evidence is a `path:line` you opened. "Probably" is `not_ok`.

## GDPR-RETENTION-ENFORCED
Ok only when BOTH exist: (a) code that deletes or anonymises the source
rows (and their files/copies) once `trigger + time_limit` has passed --
a management command, a task, a queryset `.delete()` filtered on a date;
(b) something that **runs it on a schedule**: `CELERY_BEAT_SCHEDULE`,
procrastinate `@app.periodic(cron=...)`, `snow.yml` hooks/cron, a
GitHub Actions `schedule`, a Kubernetes CronJob. An unscheduled command
is `not_ok`.

## GDPR-ERASURE-PATH
Follow every FK pointing at the source models: `on_delete=CASCADE`
erases, `SET_NULL` may leave PII in the row, `PROTECT` blocks erasure.
Check: `FileField` storage removal, history/audit tables, denormalised
columns, JSON copies in other models, task payloads still queued, email
logs, search indexes, recipients' APIs (Stripe customer deletion...).
Soft-delete (`is_deleted=True`) is not erasure. Anonymisation counts
(Recital 26) if it is irreversible.

## GDPR-ACCESS-EXPORT / GDPR-PORTABILITY
A code path serialising everything about one subject (an export view, a
management command, a privacy-app binding). Portability needs a
machine-readable format (JSON/CSV).

## GDPR-RECTIFICATION
`self_service`: an edit view/form/API the subject can use. `dpo`: no
self-service, a documented mailto/process is enough.

## GDPR-CONSENT-WITHDRAWAL / GDPR-OBJECTION
A reachable action flipping the consent/opt-out flag AND every member of
the activity honouring that flag (the newsletter task filters on it).

## GDPR-CONSENT-PROOF
Consent stored with what was consented to (version/text) and when, and
not destroyed by the account erasure path.

## GDPR-MINIMISATION
Contents no member of the activity ever reads (grep the field/JSON key
in views, tasks, templates, serializers) are collected but unused.

## GDPR-PSEUDONYMOUS-KEY / GDPR-MULTI-SUBJECT
Pseudonymous: identify the key a subject can present (cookie id, token)
and check rights are reachable with it. Multi-subject: erasure/access
must not expose or delete other people's data (redact the other party).

## GDPR-SECURITY-PII-LEAK
PII in `logger.*` calls, Sentry (`send_default_pii`, `set_user`,
`before_send` scrubbing absent), task args, email contexts, analytics.
