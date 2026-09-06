# Eval variants

Each variant is a script applied to a copy of `../template`, plus the expected
checkpoint statuses / findings after `compliance auto`. Variants are run by
`make eval` (needs `OPENROUTER_API_KEY`; not part of CI).

| variant                  | mutation                                            | expects                                                                                                                                  |
| ------------------------ | --------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `baseline`               | none                                                | leads.lead classified with email/phone/name/none; MW-SEC-001 `ok` on POST /leads/ (public form + throttle); GDPR-RETENTION-ENFORCED `ok` |
| `pii-model-added`        | adds `Patient` model with `diagnosis` TextField     | new data object with `health` item; GDPR-DPIA / SPECIAL-CATEGORY findings                                                                |
| `unauth-post`            | removes the throttle from `create_lead`             | MW-SEC-001 `not_ok`, MW-SEC-004 `not_ok`                                                                                                 |
| `sdk-added`              | imports `stripe` in api.py with `STRIPE_SECRET_KEY` | recipient `stripe` drafted; GDPR-RECIPIENT-DECLARED finding until listed                                                                 |
| `auth-removed`           | drops `AuthenticationMiddleware` from settings      | every auth-dependent checkpoint re-staged; MW-SEC-001 stays/becomes `not_ok`                                                             |
| `retention-cron-missing` | removes `CELERY_BEAT_SCHEDULE`                      | GDPR-RETENTION-ENFORCED `not_ok`                                                                                                         |
| `docs-only`              | edits a docstring                                   | nothing re-staged, zero agent calls                                                                                                      |
