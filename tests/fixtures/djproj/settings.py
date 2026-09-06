"""Settings of the introspection fixture project."""

SECRET_KEY = "test"  # noqa: S105
INSTALLED_APPS = ["django.contrib.auth", "django.contrib.contenttypes", "shop"]
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
USE_TZ = True
