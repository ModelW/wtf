"""Minimal Django-like settings for the eval fixture."""

INSTALLED_APPS = ["apps.leads", "ninja", "axes"]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "axes.middleware.AxesMiddleware",
]
AXES_FAILURE_LIMIT = 5
CELERY_BEAT_SCHEDULE = {
    "purge-leads": {"task": "apps.leads.tasks.purge_old_leads", "schedule": 86400},
}
