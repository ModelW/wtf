"""Django model introspection, executed *inside the project's interpreter*.

model-wtf never imports the audited project: this file is piped on stdin to
the project's own Python (``uv run python -``, ``poetry run python -``,
``.venv/bin/python -``), where Django and the project's apps are importable.
It must therefore stay **stdlib-only**, compatible with any Python >= 3.10,
and print exactly one JSON document to stdout; everything the project logs
during ``django.setup()`` is redirected to stderr and ignored by the caller.

Output schema (``schema: 1``)::

    {"schema": 1, "django": "5.1", "models": [
      {"app_label": "auth", "name": "User", "table": "auth_user",
       "abstract": false, "proxy": false, "module": "django.contrib.auth.models",
       "file": "/venv/lib/python3.12/site-packages/django/contrib/auth/models.py",
       "fields": [
         {"name": "email", "type": "EmailField", "internal_type": "CharField",
          "null": false, "blank": true, "primary_key": false, "unique": false,
          "max_length": 254, "choices": false, "auto_now": false,
          "relation": null}]}]}

Each model carries its ``database`` (router alias + engine/host/name) and
each file field its ``storage`` (class + bucket/location): the *store*
behind a column is a compliance fact in its own right. The payload also
lists every store the settings declare (``stores``: databases, caches, file
storages, brokers, search backends) with a stable slug; models and file
fields point at those slugs (``database.store`` / ``storage.store``).
Credentials never leave the process: passwords are dropped and URL userinfo
is stripped.

``type`` is the concrete class name so custom fields (``PhoneNumberField``,
``EncryptedCharField``) stay visible to the rules; ``internal_type`` is the
Django-level fallback. Reverse relations and generic FKs are excluded.
"""

from __future__ import annotations

import contextlib
import inspect
import json
import os
import sys

SCHEMA = 1


BUCKET_MARKERS = ("s3", "gcloud", "google", "azure", "boto", "minio", "bucket")
STATIC_ALIAS = "staticfiles"


def _strip_url(value):
    """``scheme://user:pass@host/x`` → ``scheme://host/x``; other strings as-is."""
    if not isinstance(value, str):
        return value
    if "://" in value and "@" in value:
        scheme, rest = value.split("://", 1)
        if "@" in rest.split("/", 1)[0]:
            rest = rest.split("@", 1)[1]
        return f"{scheme}://{rest}"
    return value


def _unwrap(storage):
    """``DefaultStorage``/``LazyObject`` proxies → the backend they wrap."""
    from django.utils.functional import LazyObject, empty

    if isinstance(storage, LazyObject):
        if storage._wrapped is empty:
            storage._setup()
        return storage._wrapped
    return storage


def _storage_type(cls_path):
    lowered = cls_path.lower()
    return "bucket" if any(m in lowered for m in BUCKET_MARKERS) else "filesystem"


def _storage_where(storage):
    """Bucket/location facts of a storage instance, credentials excluded."""
    where = {}
    for attr in (
        "bucket_name",
        "location",
        "base_url",
        "endpoint_url",
        "custom_domain",
        "region_name",
    ):
        value = getattr(storage, attr, None)
        if isinstance(value, str) and value:
            where[attr] = _strip_url(value)
    return where


class Stores:
    """Every store the settings declare, keyed by slug.

    Built once; ``for_storage`` then maps a field's storage instance back to
    a ``STORAGES`` alias by identity, or registers a per-field store when a
    field was given its own ``storage=`` instance.
    """

    def __init__(self):
        from django.conf import settings

        self.items = []
        self._by_storage = {}
        for alias, cfg in settings.DATABASES.items():
            where = {}
            for key in ("HOST", "NAME", "PORT"):
                if cfg.get(key):
                    where[key.lower()] = str(cfg[key])
            self._add(
                f"db-{alias}",
                "database",
                cfg.get("ENGINE", ""),
                where,
                f"DATABASES[{alias!r}]",
            )
        for alias, cfg in getattr(settings, "CACHES", {}).items():
            location = cfg.get("LOCATION")
            if isinstance(location, (list, tuple)):
                location = ", ".join(_strip_url(str(v)) for v in location)
            where = {"location": _strip_url(str(location))} if location else {}
            self._add(
                f"cache-{alias}",
                "cache",
                cfg.get("BACKEND", ""),
                where,
                f"CACHES[{alias!r}]",
            )
        self._file_storages()
        broker = getattr(settings, "CELERY_BROKER_URL", None)
        if broker:
            self._add(
                "queue-celery",
                "queue",
                str(broker).split("://", 1)[0],
                {"location": _strip_url(str(broker))},
                "CELERY_BROKER_URL",
            )
        for alias, cfg in getattr(settings, "WAGTAILSEARCH_BACKENDS", {}).items():
            urls = cfg.get("URLS") or cfg.get("URL") or []
            if isinstance(urls, str):
                urls = [urls]
            where = (
                {"location": ", ".join(_strip_url(str(u)) for u in urls)}
                if urls
                else {}
            )
            self._add(
                f"search-{alias}",
                "search",
                cfg.get("BACKEND", ""),
                where,
                f"WAGTAILSEARCH_BACKENDS[{alias!r}]",
            )
        self.sessions = self._sessions(settings)

    def _add(self, slug, kind, backend, where, config):
        self.items.append(
            {
                "slug": slug,
                "type": kind,
                "backend": backend,
                "where": where,
                "config": config,
            }
        )
        return slug

    def _file_storages(self):
        try:
            from django.core.files.storage import storages
        except ImportError:  # Django < 4.2
            from django.core.files.storage import default_storage

            storage = _unwrap(default_storage)
            cls = f"{type(storage).__module__}.{type(storage).__name__}"
            slug = self._add(
                "files-default",
                _storage_type(cls),
                cls,
                _storage_where(storage),
                "DEFAULT_FILE_STORAGE",
            )
            self._by_storage[id(storage)] = slug
            return
        for alias in storages.backends:
            if alias == STATIC_ALIAS:
                continue
            storage = _unwrap(storages[alias])
            cls = f"{type(storage).__module__}.{type(storage).__name__}"
            slug = self._add(
                f"files-{alias}",
                _storage_type(cls),
                cls,
                _storage_where(storage),
                f"STORAGES[{alias!r}]",
            )
            self._by_storage[id(storage)] = slug

    def _sessions(self, settings):
        engine = getattr(settings, "SESSION_ENGINE", "")
        if engine.endswith(".cache"):
            store = f"cache-{getattr(settings, 'SESSION_CACHE_ALIAS', 'default')}"
        elif engine.endswith((".db", ".cached_db")):
            store = "db-default"
        else:
            store = None
        return {"engine": engine, "store": store}

    def for_storage(self, storage, field_id):
        """Slug of the store behind ``storage``, registering a per-field one."""
        storage = _unwrap(storage)
        slug = self._by_storage.get(id(storage))
        if slug is None:
            cls = f"{type(storage).__module__}.{type(storage).__name__}"
            slug = self._add(
                f"files-{field_id}",
                _storage_type(cls),
                cls,
                _storage_where(storage),
                f"{field_id} storage=",
            )
            self._by_storage[id(storage)] = slug
        return slug


def _storage_info(field, stores, field_id):
    """Where a file field's bytes go: storage class, bucket/location, store slug."""
    storage = getattr(field, "storage", None)
    if storage is None:
        return None
    storage = _unwrap(storage)
    info = {"class": f"{type(storage).__module__}.{type(storage).__name__}"}
    info.update(_storage_where(storage))
    info["store"] = stores.for_storage(storage, field_id)
    return info


def _database_info(model):
    """Which configured database the model is written to, and what it is."""
    from django.conf import settings
    from django.db import router

    alias = router.db_for_write(model)
    cfg = settings.DATABASES.get(alias, {})
    info = {"alias": alias, "engine": cfg.get("ENGINE", ""), "store": f"db-{alias}"}
    for key in ("HOST", "NAME", "PORT"):
        value = cfg.get(key)
        if value:
            info[key.lower()] = str(value)
    return info


def _field_info(field, stores, model_label):  # type: ignore[no-untyped-def]
    relation = None
    remote = getattr(field, "remote_field", None)
    if remote is not None and getattr(remote, "model", None) is not None:
        target = remote.model
        if isinstance(target, str):
            to = target
        else:
            to = f"{target._meta.app_label}.{target.__name__}"
        if field.many_to_many:
            kind = "m2m"
        elif field.one_to_one:
            kind = "o2o"
        else:
            kind = "fk"
        relation = {"to": to, "kind": kind}
    try:
        internal = field.get_internal_type()
    except Exception:
        internal = type(field).__name__
    return {
        "name": field.name,
        "type": type(field).__name__,
        "internal_type": internal,
        "null": bool(getattr(field, "null", False)),
        "blank": bool(getattr(field, "blank", False)),
        "primary_key": bool(getattr(field, "primary_key", False)),
        "unique": bool(getattr(field, "unique", False)),
        "max_length": getattr(field, "max_length", None),
        "choices": bool(getattr(field, "choices", None)),
        "auto_now": bool(
            getattr(field, "auto_now", False) or getattr(field, "auto_now_add", False)
        ),
        "relation": relation,
        "storage": _storage_info(field, stores, f"{model_label}.{field.name}")
        if internal in ("FileField", "ImageField")
        else None,
    }


def main() -> int:
    """Set Django up and dump every concrete model; return the exit status."""
    # Anything the project prints while booting must not corrupt the JSON.
    real_stdout = sys.stdout
    sys.stdout = sys.stderr
    try:
        import django
        from django.apps import apps

        django.setup()
        stores = Stores()
        models = []
        for model in apps.get_models(include_auto_created=True):
            meta = model._meta
            label = f"{meta.app_label}.{model.__name__}"
            fields = []
            for field in meta.get_fields(include_hidden=False):
                # Skip reverse relations (they have no column on this model)
                # and GenericForeignKey-like virtual fields.
                if getattr(field, "auto_created", False) and not getattr(
                    field, "concrete", False
                ):
                    continue
                if not getattr(field, "concrete", True) and not field.many_to_many:
                    continue
                fields.append(_field_info(field, stores, label))
            try:
                source_file = inspect.getsourcefile(model)
            except (TypeError, OSError):
                source_file = None
            models.append(
                {
                    "app_label": meta.app_label,
                    "name": model.__name__,
                    "table": meta.db_table,
                    "abstract": bool(meta.abstract),
                    "proxy": bool(meta.proxy),
                    "module": model.__module__,
                    "file": source_file,
                    "database": _database_info(model),
                    "fields": fields,
                }
            )
        payload = {
            "schema": SCHEMA,
            "django": django.get_version(),
            "settings": os.environ.get("DJANGO_SETTINGS_MODULE"),
            # Where importable code lives: the agent needs read access to
            # these roots to inspect third-party models (auth, wagtail, ...).
            "sys_path": [p for p in sys.path if p and os.path.isdir(p)],
            "stores": stores.items,
            "sessions": stores.sessions,
            "models": models,
        }
    except Exception as exc:
        print(
            f"model-wtf introspection failed: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1
    finally:
        sys.stdout = real_stdout
    json.dump(payload, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    with contextlib.suppress(BrokenPipeError):
        sys.exit(main())
