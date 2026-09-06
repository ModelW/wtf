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
       "fields": [
         {"name": "email", "type": "EmailField", "internal_type": "CharField",
          "null": false, "blank": true, "primary_key": false, "unique": false,
          "max_length": 254, "choices": false, "auto_now": false,
          "relation": null}]}]}

``type`` is the concrete class name so custom fields (``PhoneNumberField``,
``EncryptedCharField``) stay visible to the rules; ``internal_type`` is the
Django-level fallback. Reverse relations and generic FKs are excluded.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys

SCHEMA = 1


def _field_info(field):  # type: ignore[no-untyped-def]
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
        models = []
        for model in apps.get_models(include_auto_created=True):
            meta = model._meta
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
                fields.append(_field_info(field))
            models.append(
                {
                    "app_label": meta.app_label,
                    "name": model.__name__,
                    "table": meta.db_table,
                    "abstract": bool(meta.abstract),
                    "proxy": bool(meta.proxy),
                    "module": model.__module__,
                    "fields": fields,
                }
            )
        payload = {
            "schema": SCHEMA,
            "django": django.get_version(),
            "settings": os.environ.get("DJANGO_SETTINGS_MODULE"),
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
