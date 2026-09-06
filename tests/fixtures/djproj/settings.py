"""Settings of the introspection fixture project."""

SECRET_KEY = "test"  # noqa: S105
# ``sites`` is a third-party app with no library knowledge: its fields go
# through the rules and the review like the project's own.
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.sites",
    "django.contrib.admin",
    "django.contrib.messages",
    "procrastinate.contrib.django",
    "shop",
]
SITE_ID = 1
ROOT_URLCONF = "urls"
MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]
PROCRASTINATE_ON_APP_READY = "shop.tasks.setup"
DATABASES = {
    "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"},
    # A second database, routed to by ``shop.routers.AuditRouter`` for the
    # audit model, so store slugs follow the router and not just "default".
    "audit": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
        "PASSWORD": "must-not-leak",
    },
}
DATABASE_ROUTERS = ["shop.routers.AuditRouter"]
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": "redis://user:secret@cache.internal:6379/1",
    }
}
USE_TZ = True
