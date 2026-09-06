---
name: threat-django
description: How MW-SEC and pytm rules manifest in Django / Ninja / DRF / Wagtail, and what evidence proves mitigation.
---

# Django stack: evidence per rule

Always check the **global** layer before the route: `MIDDLEWARE`,
`REST_FRAMEWORK` defaults, Ninja `NinjaAPI(auth=...)`, `LOGIN_URL`,
django-axes / ratelimit settings, `SECURE_*` settings, Wagtail
`WAGTAILADMIN_BASE_URL`.

- **MW-SEC-001 unauth mutating route**: mutating verb + no auth. Ninja:
  `router.post(..., auth=None)` or API without default auth; DRF:
  `permission_classes = [AllowAny]` or no `DEFAULT_PERMISSION_CLASSES`;
  plain views without `login_required`/`LoginRequiredMixin`. Public forms
  are `ok` only with throttling + intent documented.
- **MW-SEC-002 upload validation**: `FileField`/`ImageField` or
  `request.FILES`: look for `validators=[FileExtensionValidator...]`,
  size checks, content sniffing (`python-magic`), storage outside the app
  origin, `Content-Disposition: attachment`.
- **MW-SEC-003 admin/debug/docs public**: `/admin/`, `/docs`, `/openapi`,
  `/__debug__/`, `/silk/`, `/graphiql` in urlconf; check which ingress
  serves them (snow.yml components/domains) and `DEBUG`.
- **MW-SEC-004 rate limiting**: auth/OTP/reset/signup and PII-returning
  routes: `django-axes` (`AXES_*`), DRF `throttle_classes`, Ninja
  `throttle=`, `django-ratelimit`, or an edge limiter declared as an
  assumption.
- **MW-SEC-005 PII to sinks**: `logging` of request bodies/users, Sentry
  `send_default_pii`, `sentry_sdk.set_user`, `before_send`.
- **MW-SEC-006 webhooks**: Stripe `Webhook.construct_event`, HMAC
  comparisons with `hmac.compare_digest`, timestamp checks, done **before**
  any side effect.
- **MW-SEC-007 IDOR**: querysets filtered on `request.user` /
  `owner=`, `get_object_or_404(Model, pk=pk, owner=request.user)`,
  object permissions (`django-guardian`, DRF `has_object_permission`).
- **MW-SEC-008 mass assignment**: `fields = "__all__"`, `**request.data`,
  `Model(**payload)`, `update(**data)`; ok when an explicit schema /
  serializer whitelists fields.
- **MW-SEC-009 secrets**: literals shaped like keys, `SECRET_KEY`
  defaults, logging of headers/settings dicts.
- **pytm INP/AA/AC/CR/DO/DS rules**: map to the closest Django control:
  CSRF middleware + `SESSION_COOKIE_SECURE`/`HTTPONLY`, `ALLOWED_HOSTS`,
  `SECURE_HSTS_SECONDS`, `X_FRAME_OPTIONS`, password validators, ORM
  (no raw SQL with f-strings), template autoescape.

`depends_on` for Django almost always includes `settings.py#MIDDLEWARE`
or the relevant settings symbol plus the view/router file.
