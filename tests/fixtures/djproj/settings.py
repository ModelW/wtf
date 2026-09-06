"""Settings of the introspection fixture project."""

SECRET_KEY = "test"  # noqa: S105
# ``sites`` is a third-party app with no library knowledge: its fields go
# through the rules and the review like the project's own.
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.sites",
    "shop",
]
SITE_ID = 1
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
