"""In-venv Django introspection: prints Surface JSON (``modelw.surface/1``).

This file is piped into the *project's* interpreter (``uv run python -``,
``poetry run python -``, ``.venv/bin/python -``) by model-wtf. It must
therefore stay self-contained: standard library + Django only, no import
of the tool's own package, no third-party dependency that a random Django repo
may lack. Optional frameworks (Ninja, DRF, Wagtail, Channels, Celery,
Procrastinate) are probed with try/except and simply skipped when absent.

Nothing here needs a database: ``django.setup()`` is enough to walk the
URL resolver, the app registry and the settings.
"""

from __future__ import annotations

import argparse
import ast  # noqa: TC003 - used at runtime
import inspect
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

EXTRACTOR_VERSION = 1
SCHEMA_ID = "modelw.surface/1"

PII_HINTS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"e-?mail", re.I), "email", "high"),
    (
        re.compile(r"^(first|last|full|display|middle)?_?name$|_name$", re.I),
        "name",
        "high",
    ),
    (re.compile(r"phone|mobile|tel(ephone)?$|msisdn", re.I), "phone", "high"),
    (
        re.compile(r"address|street|zip|postal|postcode|city$", re.I),
        "address",
        "medium",
    ),
    (
        re.compile(r"iban|bic|card|amount|price|total|invoice|salary|vat", re.I),
        "financial",
        "medium",
    ),
    (
        re.compile(r"password|passwd|secret|token|api_key|otp|totp", re.I),
        "credential",
        "high",
    ),
    (
        re.compile(r"lat(itude)?$|lng$|lon(gitude)?$|geo|location|position|gps", re.I),
        "location",
        "medium",
    ),
    (re.compile(r"birth|dob$|gender|age$", re.I), "identifier", "medium"),
    (re.compile(r"health|diagnos|medical|allerg", re.I), "health", "medium"),
    (
        re.compile(r"ip_?address|user_?agent|device|fingerprint", re.I),
        "identifier",
        "medium",
    ),
    (
        re.compile(r"comment|note|message|description|bio$|free_?text|body$", re.I),
        "free_text",
        "low",
    ),
]
OPAQUE_FIELDS = {
    "JSONField",
    "TextField",
    "BinaryField",
    "StreamField",
    "RichTextField",
    "HStoreField",
}
BLOB_FIELDS = {"FileField", "ImageField"}
# Env-key prefixes -> well-known third party (public SaaS only; project-
# specific integrations are for the agent to classify). Specific prefixes
# come before the generic credential suffixes.
SINK_HINTS: list[tuple[re.Pattern[str], str | None]] = [
    (re.compile(r"^SENTRY_|_SENTRY_DSN$"), "sentry"),
    (
        re.compile(r"^AWS_|^DO_SPACES?_|^S3_|^STORAGES?_|^DO_REGION$|^DO_API_TOKEN$"),
        "digitalocean-spaces",
    ),
    (
        re.compile(
            r"^GS_BUCKET|^GCP_|^GOOGLE_SERVICE_ACCOUNT|^G_(PROJECT|PRIVATE|CLIENT|TYPE)"
        ),
        "google-cloud",
    ),
    (re.compile(r"^GOOGLE_SSO_"), "google-sso"),
    (re.compile(r"^GOOGLE_(MAPS_)?API_KEY$"), "google-maps"),
    (re.compile(r"^MAPBOX_"), "mapbox"),
    (re.compile(r"^DATABASE_URL$|^ERP_DATABASE_URL$|^POSTGRES_"), "database"),
    (re.compile(r"^REDIS_URL$|^CELERY_BROKER_URL$"), "redis"),
    (re.compile(r"^MAILCHIMP_|^MANDRILL_"), "mandrill"),
    (re.compile(r"^BREVO_|^SENDINBLUE_"), "brevo"),
    (re.compile(r"^RESEND_"), "resend"),
    (re.compile(r"^WAILER_FROM|^DEFAULT_FROM_EMAIL$|^EMAIL_MODE$|^EMAIL_"), "email"),
    (re.compile(r"^STRIPE_"), "stripe"),
    (re.compile(r"^YOUSIGN_"), "yousign"),
    (re.compile(r"^DOCUSIGN_"), "docusign"),
    (re.compile(r"^SLACK_"), "slack"),
    (re.compile(r"^SHOPIFY_"), "shopify"),
    (re.compile(r"^PIPEDRIVE_"), "pipedrive"),
    (re.compile(r"^MATOMO_"), "matomo"),
    (re.compile(r"^TAG_COMMANDER_"), "tag-commander"),
    (re.compile(r"^MOESIF_"), "moesif"),
    (re.compile(r"^RECAPTCHA_"), "recaptcha"),
    (re.compile(r"^MISTRAL_"), "mistral"),
    (re.compile(r"^ANTHROPIC_"), "anthropic"),
    (re.compile(r"^LINEAR_"), "linear"),
    (re.compile(r"^GITHUB_"), "github"),
    (
        re.compile(r"_API_KEY$|_SECRET(_KEY)?$|_TOKEN$|_DSN$|_PASSWORD$|_PRIVATE_KEY$"),
        None,
    ),
]
SDK_PACKAGES = {
    "sentry_sdk": "sentry",
    "stripe": "stripe",
    "boto3": "digitalocean-spaces",
    "storages": "digitalocean-spaces",
    "mailchimp_transactional": "mandrill",
    "anymail": "mandrill",
    "sib_api_v3_sdk": "brevo",
    "yousign": "yousign",
    "requests": None,
    "httpx": None,
}
INFRA_TAGS = {
    "admin": re.compile(r"^/?(back/)?(admin|django-admin)(/|$)"),
    "cms-admin": re.compile(r"(^|/)(cms|wagtail)(/|$)"),
    "cms-preview": re.compile(r"preview"),
    "health": re.compile(r"health|ping|ready|live"),
    "debug-only": re.compile(r"__debug__|silk|graphiql"),
    "openapi-docs": re.compile(r"/docs/?$|openapi\.json$|/schema/?$"),
    "documents": re.compile(r"(^|/)documents(/|$)"),
}


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------


def _settings_module(context: Path) -> str | None:
    env = os.environ.get("DJANGO_SETTINGS_MODULE")
    if env:
        return env
    manage = context / "manage.py"
    if manage.is_file():
        match = re.search(
            r"DJANGO_SETTINGS_MODULE[\"']\s*,\s*[\"']([\w.]+)[\"']", manage.read_text()
        )
        if match:
            return match.group(1)
    return None


def _load_env_file(path: Path) -> None:
    """Minimal ``KEY=value`` loader so settings that read env can import."""
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def _bootstrap(context: Path, env_file: Path | None) -> None:
    sys.path.insert(0, str(context))
    for candidate in (
        [env_file] if env_file else [context / ".env", context.parent / ".env"]
    ):
        if candidate and candidate.is_file():
            _load_env_file(candidate)
    module = _settings_module(context)
    if module is None:
        _fail("cannot determine DJANGO_SETTINGS_MODULE (set it or add manage.py)")
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", module)
    # Settings frequently require these to import; harmless placeholders.
    os.environ.setdefault("SECRET_KEY", "model-wtf-introspection")
    os.environ.setdefault("DATABASE_URL", "postgres://x:x@localhost/x")
    os.environ.setdefault("REDIS_URL", "redis://localhost/0")
    os.environ.setdefault("BASE_URL", "http://localhost")
    import django

    django.setup()


def _fail(message: str) -> None:
    sys.stderr.write(f"model-wtf introspect: {message}\n")
    sys.exit(2)


def _provenance(obj: Any) -> str | None:
    try:
        target = inspect.unwrap(obj)
        if hasattr(target, "view_class"):
            target = target.view_class
        file = inspect.getsourcefile(target)
        line = inspect.getsourcelines(target)[1]
    except (TypeError, OSError):
        return None
    if not file:
        return None
    try:
        rel = Path(file).resolve().relative_to(Path.cwd().resolve())
    except ValueError:
        return f"{file}:{line}"
    return f"{rel.as_posix()}:{line}"


# ---------------------------------------------------------------------------
# Entrypoints
# ---------------------------------------------------------------------------


def _tags(path: str) -> list[str]:
    return sorted(tag for tag, rx in INFRA_TAGS.items() if rx.search(path))


def _auth_of_view(view: Any) -> dict[str, Any]:
    target = getattr(view, "view_class", view)
    auth: dict[str, Any] = {"scheme": "unknown", "permissions": []}
    src_names = set()
    try:
        src_names = {n for n in dir(target)}
    except Exception:
        pass
    # DRF
    perms = getattr(target, "permission_classes", None)
    if perms is not None:
        names = [getattr(p, "__name__", str(p)) for p in perms]
        auth["permissions"] = names
        auth["scheme"] = "none" if "AllowAny" in names or not names else "token"
        return auth
    # Class-based views with LoginRequiredMixin
    bases = {b.__name__ for b in getattr(target, "__mro__", ())}
    if "LoginRequiredMixin" in bases or "PermissionRequiredMixin" in bases:
        auth["scheme"] = "session"
        return auth
    if (
        getattr(inspect.unwrap(view), "login_required", False)
        or "login_required" in src_names
    ):
        auth["scheme"] = "session"
    closure = getattr(view, "__wrapped__", None)
    if closure is not None and view is not closure:
        qual = getattr(view, "__qualname__", "")
        if "login_required" in qual or "permission_required" in qual:
            auth["scheme"] = "session"
    return auth


def _source_file(obj: Any) -> str | None:
    try:
        target = inspect.unwrap(obj)
        if hasattr(target, "view_class"):
            target = target.view_class
        return inspect.getsourcefile(target)
    except (TypeError, OSError):
        return None


def _django_entrypoints(context: Path) -> list[dict[str, Any]]:
    from django.urls import URLPattern, URLResolver, get_resolver

    out: list[dict[str, Any]] = []

    def walk(patterns: Any, prefix: str, namespace: str | None) -> None:
        for entry in patterns:
            if isinstance(entry, URLResolver):
                ns = entry.namespace or namespace
                walk(entry.url_patterns, prefix + _pattern_str(entry.pattern), ns)
            elif isinstance(entry, URLPattern):
                path = "/" + (prefix + _pattern_str(entry.pattern)).lstrip("/")
                view = entry.callback
                if getattr(view, "__module__", "").startswith(
                    ("ninja.", "rest_framework.", "wagtail.")
                ):
                    continue  # framework-mounted; handled by the dedicated probes
                qual = getattr(view, "__qualname__", getattr(view, "__name__", "?"))
                dotted = f"{getattr(view, '__module__', '?')}.{qual}"
                methods = _view_methods(view)
                if not _in_project(_source_file(view), context):
                    continue  # third-party views (admin, wagtail, debug toolbar...)
                access = _model_access_of_file(
                    _source_file(view), context, getattr(view, "__qualname__", None)
                )
                for method in methods:
                    out.append(
                        {
                            "id": f"http:{method}:{path}",
                            "path": path,
                            "methods": [method],
                            "view": dotted,
                            "namespace": namespace,
                            "name": entry.name,
                            "auth": _auth_of_view(view),
                            "tags": _tags(path),
                            "provenance": _provenance(view),
                            **access,
                        }
                    )

    walk(get_resolver().url_patterns, "", None)
    return out


def _pattern_str(pattern: Any) -> str:
    text = str(pattern)
    text = re.sub(r"\^|\$", "", text)
    text = re.sub(r"\(\?P<(\w+)>[^)]*\)", r"<\1>", text)
    return text


def _view_methods(view: Any) -> list[str]:
    cls = getattr(view, "view_class", None)
    if cls is not None:
        allowed = [
            m.upper()
            for m in getattr(cls, "http_method_names", [])
            if hasattr(cls, m) and m not in ("options", "head")
        ]
        return allowed or ["GET"]
    return ["GET"]


def _ninja_entrypoints(context: Path) -> list[dict[str, Any]]:
    try:
        from ninja import NinjaAPI
    except ImportError:
        return []
    out: list[dict[str, Any]] = []
    for mount, api in _ninja_apis(NinjaAPI):
        for prefix, router in api._routers:
            for path, path_view in router.path_operations.items():
                for op in path_view.operations:
                    full = _join(mount, prefix, path)
                    auth = _ninja_auth(op, router, api)
                    access = _model_access_of_file(
                        _source_file(op.view_func), context, op.view_func.__qualname__
                    )
                    for method in op.methods:
                        out.append(
                            {
                                "id": f"http:{method}:{full}",
                                "path": full,
                                "methods": [method],
                                "view": (
                                    f"{op.view_func.__module__}."
                                    f"{op.view_func.__qualname__}"
                                ),
                                "auth": auth,
                                "params": _ninja_params(op),
                                "tags": _tags(full),
                                "provenance": _provenance(op.view_func),
                                **access,
                            }
                        )
    return out


def _ninja_apis(cls: type) -> list[tuple[str, Any]]:
    """``(mount prefix, NinjaAPI)`` pairs found in the URL tree.

    Ninja mounts its views as ``functools.partial(view, api=<NinjaAPI>)``,
    so the API instance is recovered from the partial's keywords; the
    mount is the resolver prefix leading to it.
    """
    import functools

    from django.urls import URLResolver, get_resolver

    found: list[tuple[str, Any]] = []
    seen: set[int] = set()

    def walk(patterns: Any, prefix: str) -> None:
        for entry in patterns:
            if isinstance(entry, URLResolver):
                walk(entry.url_patterns, prefix + _pattern_str(entry.pattern))
                continue
            callback = getattr(entry, "callback", None)
            api = None
            if isinstance(callback, functools.partial):
                api = callback.keywords.get("api")
            if api is None:
                api = getattr(callback, "__self__", None)
            if isinstance(api, cls) and id(api) not in seen:
                seen.add(id(api))
                found.append(("/" + prefix.strip("/"), api))

    walk(get_resolver().url_patterns, "")
    return found


def _join(*parts: str) -> str:
    joined = "/".join(p.strip("/") for p in parts if p and p.strip("/"))
    path = "/" + joined
    return path if path.endswith("/") or not parts[-1].endswith("/") else path + "/"


def _ninja_auth(op: Any, router: Any, api: Any) -> dict[str, Any]:
    """Effective auth: operation, else router, else API default.

    Ninja keeps ``auth_param`` as NOT_SET when an operation inherits; the
    first *set* value in the chain wins, and an explicit ``None`` anywhere
    means deliberately public.
    """
    not_set = "NOT_SET_TYPE"
    chosen: Any = None
    for value in (
        getattr(op, "auth_param", None),
        getattr(router, "auth", None),
        getattr(api, "auth", None),
    ):
        if type(value).__name__ == not_set:
            continue
        chosen = value
        break
    if not chosen:
        return {"scheme": "none", "permissions": []}
    callbacks = list(chosen) if isinstance(chosen, (list, tuple)) else [chosen]
    names = [
        type(c).__name__ if not inspect.isfunction(c) else c.__name__ for c in callbacks
    ]
    scheme = (
        "session"
        if any("session" in n.lower() or "django" in n.lower() for n in names)
        else "token"
    )
    return {"scheme": scheme, "permissions": names}


def _ninja_params(op: Any) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for model in getattr(op, "models", []) or []:
        kind = getattr(model, "__ninja_param_source__", None) or getattr(
            model, "_in", None
        )
        name = getattr(model, "__name__", str(model))
        if kind:
            params.setdefault(str(kind), []).append(name)
    if any("file" in str(k).lower() for k in params):
        params["files"] = True
    return params


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


def _pii_hints(name: str, ftype: str) -> list[dict[str, str]]:
    if ftype == "EmailField":
        return [{"item": "email", "confidence": "high"}]
    hints = [
        {"item": item, "confidence": conf}
        for rx, item, conf in PII_HINTS
        if rx.search(name)
    ]
    return hints[:2]


def _candidate_contents(
    model: Any, field_name: str, context: Path
) -> list[dict[str, Any]]:
    """Keys seen written into an opaque field: grep the app's sources."""
    app_dir = Path(inspect.getsourcefile(model) or "").parent
    seen: dict[str, str] = {}
    rx = re.compile(
        rf"{re.escape(field_name)}\s*(?:\[|\.get\(|=\s*\{{)[\"']?([A-Za-z_][A-Za-z0-9_]*)"
    )
    dict_rx = re.compile(rf"{re.escape(field_name)}\s*=\s*\{{([^}}]*)\}}")
    for file in list(app_dir.rglob("*.py"))[:200]:
        try:
            text = file.read_text(encoding="utf-8")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for match in rx.finditer(line):
                seen.setdefault(match.group(1), f"{_rel(file, context)}:{lineno}")
            for match in dict_rx.finditer(line):
                for key in re.findall(
                    r"[\"']([A-Za-z_][A-Za-z0-9_]*)[\"']\s*:", match.group(1)
                ):
                    seen.setdefault(key, f"{_rel(file, context)}:{lineno}")
    return [{"name": k, "provenance": v} for k, v in sorted(seen.items())][:40]


def _rel(file: Path, context: Path) -> str:
    try:
        return file.resolve().relative_to(context.resolve()).as_posix()
    except ValueError:
        return str(file)


def _storage(context: Path) -> list[dict[str, Any]]:
    from django.apps import apps
    from django.conf import settings
    from django.db import router

    shadow_apps = {
        "sessions",
        "admin",
        "contenttypes",
        "auth",
        "wagtailcore",
        "django_celery_results",
        "procrastinate",
        "axes",
    }
    out: list[dict[str, Any]] = []
    for model in apps.get_models():
        meta = model._meta
        fields: list[dict[str, Any]] = []
        chain: str | None = None
        history = any(
            "HistoricalRecords" in type(f).__name__ for f in vars(model).values()
        ) or hasattr(model, "history")
        soft_delete = any(
            f.name in ("deleted", "is_deleted", "deleted_at")
            for f in meta.get_fields()
            if hasattr(f, "name")
        )
        blob = False
        pk_pii = False
        for f in [*meta.concrete_fields, *meta.many_to_many]:
            ftype = type(f).__name__
            spec: dict[str, Any] = {
                "name": f.name,
                "type": ftype,
                "null": bool(getattr(f, "null", False)),
                "unique": bool(getattr(f, "unique", False)),
                "primary_key": bool(getattr(f, "primary_key", False)),
            }
            if getattr(f, "choices", None):
                spec["choices"] = [str(c[0]) for c in f.choices][:20]
            remote = getattr(f, "remote_field", None)
            if remote is not None and getattr(remote, "model", None) is not None:
                target = remote.model
                spec["fk_target"] = f"store:{target._meta.app_label}.{target.__name__}"
                on_delete = getattr(remote, "on_delete", None)
                if on_delete is not None:
                    spec["on_delete"] = getattr(on_delete, "__name__", str(on_delete))
                    if spec["on_delete"] in ("DO_NOTHING", "PROTECT"):
                        chain = spec["on_delete"]
            hints = _pii_hints(f.name, ftype)
            if hints:
                spec["pii_hints"] = hints
            if ftype in OPAQUE_FIELDS:
                spec["opaque"] = True
                if ftype == "JSONField":
                    spec["candidate_contents"] = _candidate_contents(
                        model, f.name, context
                    )
            if ftype in BLOB_FIELDS:
                blob = True
                spec["pii_hints"] = spec.get("pii_hints") or [
                    {"item": "free_text", "confidence": "low"}
                ]
            if (
                spec["primary_key"]
                and ftype in ("EmailField", "CharField")
                and _pii_hints(f.name, ftype)
            ):
                pk_pii = True
            fields.append(spec)
        out.append(
            {
                "id": f"store:{meta.app_label}.{model.__name__}",
                "app_label": meta.app_label,
                "model": model.__name__,
                "database": router.db_for_write(model)
                if hasattr(settings, "DATABASES")
                else None,
                "shadow_store": meta.app_label in shadow_apps
                or model.__name__ in ("Session", "LogEntry", "Email"),
                "lifecycle": {
                    "soft_delete": soft_delete,
                    "history": history,
                    "blob": blob,
                    "pk_as_pii": pk_pii,
                    **({"on_delete_chain": chain} if chain else {}),
                },
                "fields": fields,
                "provenance": _provenance(model),
            }
        )
    return out


# ---------------------------------------------------------------------------
# Config / egress / tasks / controls
# ---------------------------------------------------------------------------


def _config(context: Path) -> list[dict[str, Any]]:
    from django.conf import settings

    keys: dict[str, dict[str, Any]] = {}
    used = getattr(settings, "USED_ENV_VARS", None)
    if isinstance(used, dict):
        for key, meta in used.items():
            keys[key] = {
                "key": key,
                "required": bool(
                    getattr(meta, "required", meta.get("required", False))
                    if not isinstance(meta, dict)
                    else meta.get("required", False)
                ),
                "is_yaml": bool(meta.get("is_yaml", False))
                if isinstance(meta, dict)
                else bool(getattr(meta, "is_yaml", False)),
            }
    # Fallback: grep settings sources for environ reads.
    rx = re.compile(
        r"(?:environ(?:\.get)?\(|getenv\(|env\(|\.get\()\s*[\"']([A-Z][A-Z0-9_]+)[\"']"
    )
    for file in _settings_files(context):
        for match in rx.finditer(file.read_text(encoding="utf-8", errors="replace")):
            keys.setdefault(
                match.group(1),
                {"key": match.group(1), "required": False, "is_yaml": False},
            )
    out: list[dict[str, Any]] = []
    for key in sorted(keys):
        entry = keys[key]
        for rx_sink, sink in SINK_HINTS:
            if rx_sink.search(key):
                if sink:
                    entry["sink"] = sink
                if re.search(r"KEY|SECRET|TOKEN|PASSWORD|DSN|PRIVATE", key):
                    entry["secret"] = True
                break
        out.append(entry)
    return out


def _settings_files(context: Path) -> list[Path]:
    module = os.environ.get("DJANGO_SETTINGS_MODULE", "")
    files: list[Path] = []
    if module:
        try:
            mod = sys.modules.get(module) or __import__(module, fromlist=["_"])
            file = getattr(mod, "__file__", None)
            if file:
                files.append(Path(file))
        except Exception:
            pass
    return files


def _egress(context: Path) -> list[dict[str, Any]]:
    from django.conf import settings

    out: dict[str, dict[str, Any]] = {}
    for pkg, slug in SDK_PACKAGES.items():
        if pkg in sys.modules or _importable(pkg):
            if slug is None:
                continue
            entry = out.setdefault(
                f"egress:sdk:{pkg}",
                {
                    "id": f"egress:sdk:{pkg}",
                    "credential_keys": [],
                    "facts": {},
                    "provenance": [],
                },
            )
            if pkg == "sentry_sdk":
                try:
                    import sentry_sdk

                    client = (
                        sentry_sdk.get_client()
                        if hasattr(sentry_sdk, "get_client")
                        else None
                    )
                    opts = getattr(client, "options", {}) or {}
                    entry["facts"] = {
                        "send_default_pii": bool(opts.get("send_default_pii", False)),
                        "replay": bool(
                            opts.get("_experiments", {}).get(
                                "replay_session_sample_rate"
                            )
                            or 0
                        ),
                    }
                except Exception:
                    pass
                entry["credential_keys"] = [
                    k
                    for k in ("SENTRY_DSN",)
                    if k in os.environ or hasattr(settings, k)
                ]
            if pkg in ("boto3", "storages"):
                entry["credential_keys"] = sorted(
                    k
                    for k in (
                        "AWS_ACCESS_KEY_ID",
                        "AWS_SECRET_ACCESS_KEY",
                        "AWS_S3_ENDPOINT_URL",
                        "AWS_STORAGE_BUCKET_NAME",
                    )
                    if hasattr(settings, k) or k in os.environ
                )
                host = getattr(settings, "AWS_S3_ENDPOINT_URL", None) or getattr(
                    settings, "AWS_S3_CUSTOM_DOMAIN", None
                )
                if host:
                    out.setdefault(
                        f"egress:host:{_host(str(host))}",
                        {
                            "id": f"egress:host:{_host(str(host))}",
                            "credential_keys": entry["credential_keys"],
                            "facts": {},
                            "provenance": [],
                        },
                    )
    # Hosts named in settings.
    for name in dir(settings):
        if name.startswith("_"):
            continue
        try:
            value = getattr(settings, name)
        except Exception:
            continue
        if isinstance(value, str) and re.match(r"https?://", value):
            host = _host(value)
            if (
                host
                and not re.match(
                    r"^(localhost|127\.|0\.0\.0\.0|\[::|api$|front$|tmw$)", host
                )
                and "." in host
            ):
                out.setdefault(
                    f"egress:host:{host}",
                    {
                        "id": f"egress:host:{host}",
                        "credential_keys": [],
                        "facts": {},
                        "provenance": [],
                    },
                )
                out[f"egress:host:{host}"]["credential_keys"] = sorted(
                    set(out[f"egress:host:{host}"]["credential_keys"]) | {name}
                )
    return [out[k] for k in sorted(out)]


def _host(url: str) -> str:
    return re.sub(r"^https?://", "", url).split("/", 1)[0].split("@")[-1].split(":")[0]


def _importable(pkg: str) -> bool:
    import importlib.util

    try:
        return importlib.util.find_spec(pkg) is not None
    except (ImportError, ValueError):
        return False


def _tasks(context: Path) -> list[dict[str, Any]]:
    from django.conf import settings

    out: list[dict[str, Any]] = []
    out.extend(_procrastinate_tasks(context))
    beat = getattr(settings, "CELERY_BEAT_SCHEDULE", None) or {}
    for entry in beat.values():
        task = entry.get("task")
        if task:
            out.append(
                {
                    "id": f"task:{task}",
                    "kind": "celery",
                    "schedule": str(entry.get("schedule")),
                }
            )
    out.extend(_project_commands(context))
    seen: set[str] = set()
    unique = []
    for t in out:
        if t["id"] not in seen:
            seen.add(t["id"])
            unique.append(t)
    return sorted(unique, key=lambda t: t["id"])


def _procrastinate_tasks(context: Path) -> list[dict[str, Any]]:
    """Tasks of ``procrastinate.contrib.django`` (autodiscovered ``tasks.py``)."""
    try:
        from procrastinate.contrib.django import app
    except Exception:
        return []
    try:
        import importlib

        from django.apps import apps as django_apps

        for config in django_apps.get_app_configs():
            try:
                importlib.import_module(f"{config.name}.tasks")
            except Exception:
                continue
    except Exception:
        pass
    out: list[dict[str, Any]] = []
    for task_name, task in getattr(app, "tasks", {}).items():
        func = getattr(task, "func", task)
        if not _in_project(_source_file(func), context):
            continue
        out.append(
            {
                "id": f"task:{task_name}",
                "kind": "procrastinate",
                "schedule": _periodic(app, task),
                "provenance": _provenance(func),
                **_model_access_of_file(
                    _source_file(func), context, getattr(func, "__qualname__", None)
                ),
            }
        )
    return out


def _project_commands(context: Path) -> list[dict[str, Any]]:
    """Management commands whose source lives in the project."""
    import importlib

    from django.core.management import get_commands

    out: list[dict[str, Any]] = []
    for command, app in get_commands().items():
        try:
            module = importlib.import_module(f"{app}.management.commands.{command}")
        except Exception:
            continue
        file = getattr(module, "__file__", None)
        if not _in_project(file, context):
            continue
        out.append(
            {
                "id": f"task:{app}.management.commands.{command}",
                "kind": "command",
                "provenance": f"{_rel(Path(file), context)}:1" if file else None,
                **_model_access_of_file(file, context),
            }
        )
    return out


def _in_project(file: str | None, context: Path) -> bool:
    """Whether ``file`` is the project's own code (not site-packages / venv)."""
    if not file:
        return False
    try:
        rel = Path(file).resolve().relative_to(context.resolve())
    except ValueError:
        return False
    return not {".venv", "venv", "site-packages", "node_modules"} & set(rel.parts)


_MODEL_INDEX: dict[str, str] = {}


def _model_index() -> dict[str, str]:
    """``ModelName`` / ``app.ModelName`` -> ``store:app.Model`` for access analysis."""
    if _MODEL_INDEX:
        return _MODEL_INDEX
    from django.apps import apps

    for model in apps.get_models():
        store = f"store:{model._meta.app_label}.{model.__name__}"
        _MODEL_INDEX.setdefault(model.__name__, store)
        _MODEL_INDEX[f"{model._meta.app_label}.{model.__name__}"] = store
    return _MODEL_INDEX


_WRITE_METHODS = {
    "create",
    "update",
    "save",
    "delete",
    "bulk_create",
    "bulk_update",
    "get_or_create",
    "update_or_create",
    "objects.create",
}
_READ_METHODS = {
    "get",
    "filter",
    "all",
    "exists",
    "count",
    "first",
    "last",
    "values",
    "values_list",
    "get_object_or_404",
    "select_related",
    "prefetch_related",
    "aggregate",
    "annotate",
    "exclude",
}


def _model_access_of_file(
    file: str | None, context: Path, function: str | None = None
) -> dict[str, Any]:
    """Best-effort AST: which models a module (or one function) reads/writes.

    ``Model.objects.<method>`` chains are attributed to the model; the
    method decides read vs write. ``ModelName(...)`` + ``.save()``, and
    ``.delete()`` on anything, count as writes to every model the
    function references. Precision is what the agent is for; this is the
    hint it starts from.
    """
    import ast

    empty = {"models_read": [], "models_written": [], "access_confidence": None}
    if not file or not _in_project(file, context):
        return empty
    try:
        tree = ast.parse(Path(file).read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return empty
    index = _model_index()
    nodes: list[ast.AST] = [tree]
    if function:
        wanted = function.split(".")[-1]
        nodes = [
            n
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and n.name == wanted
        ] or [tree]
    read: set[str] = set()
    written: set[str] = set()
    for root_node in nodes:
        for node in ast.walk(root_node):
            if not isinstance(node, ast.Call):
                continue
            chain = _attr_chain(node.func)
            if not chain:
                continue
            model = next((index[c] for c in chain if c in index), None)
            if model is None:
                continue
            method = chain[-1]
            if method in _WRITE_METHODS or (method == "objects" and False):
                written.add(model)
            elif method in _READ_METHODS or "objects" in chain:
                read.add(model)
            elif chain[-1] in index:
                written.add(model)  # Model(...) constructor -> likely save
    if not read and not written:
        return empty
    return {
        "models_read": sorted(read),
        "models_written": sorted(written),
        "access_confidence": "low" if function is None else "medium",
    }


def _attr_chain(node: ast.AST) -> list[str]:
    import ast

    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.extend(_attr_chain(node.func))
    return list(reversed(parts))


def _periodic(app: Any, task: Any) -> str | None:
    registry = getattr(
        getattr(app, "periodic_registry", None), "periodic_tasks", None
    ) or getattr(getattr(app, "periodic_deferrer", None), "periodic_tasks", None)
    if not registry:
        return None
    for periodic in registry if isinstance(registry, list) else registry.values():
        if getattr(periodic, "task", None) is task:
            return str(getattr(periodic, "cron", None))
    return None


def _controls() -> dict[str, Any]:
    from django.conf import settings

    middleware = list(getattr(settings, "MIDDLEWARE", []))
    return {
        "csrf_middleware": any("CsrfViewMiddleware" in m for m in middleware),
        "session_cookie_secure": bool(
            getattr(settings, "SESSION_COOKIE_SECURE", False)
        ),
        "session_cookie_httponly": bool(
            getattr(settings, "SESSION_COOKIE_HTTPONLY", True)
        ),
        "session_cookie_samesite": getattr(settings, "SESSION_COOKIE_SAMESITE", None),
        "secure_proxy_ssl_header": bool(
            getattr(settings, "SECURE_PROXY_SSL_HEADER", None)
        ),
        "allowed_hosts": list(getattr(settings, "ALLOWED_HOSTS", [])),
        "cors": {
            k: getattr(settings, k)
            for k in dir(settings)
            if k.startswith("CORS_")
            and isinstance(getattr(settings, k, None), (bool, list, str))
        },
        "debug": bool(getattr(settings, "DEBUG", False)),
        "axes": {
            k: getattr(settings, k)
            for k in dir(settings)
            if k.startswith("AXES_")
            and isinstance(getattr(settings, k, None), (bool, int, str))
        },
        "password_validators": [
            v.get("NAME", "").rsplit(".", 1)[-1]
            for v in getattr(settings, "AUTH_PASSWORD_VALIDATORS", [])
        ],
        "clearsessions_scheduled": False,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    """Parse flags, bootstrap Django, print the Surface."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--context", default=".")
    parser.add_argument("--unit", default="api")
    parser.add_argument("--env-file", default=None)
    args = parser.parse_args()
    context = Path(args.context).resolve()
    os.chdir(context)
    _bootstrap(context, Path(args.env_file) if args.env_file else None)

    stack = ["django"]
    for pkg, name in (
        ("ninja", "ninja"),
        ("rest_framework", "drf"),
        ("wagtail", "wagtail"),
        ("channels", "channels"),
        ("procrastinate", "procrastinate"),
        ("celery", "celery"),
    ):
        if _importable(pkg):
            stack.append(name)
    entrypoints = _django_entrypoints(context) + _ninja_entrypoints(context)
    surface = {
        "schema": SCHEMA_ID,
        "extractor_version": EXTRACTOR_VERSION,
        "unit": args.unit,
        "stack": stack,
        "entrypoints": sorted(entrypoints, key=lambda e: e["id"]),
        "storage": sorted(_storage(context), key=lambda s: s["id"]),
        "config": _config(context),
        "egress": _egress(context),
        "tasks": _tasks(context),
        "controls": _controls(),
    }
    json.dump(surface, sys.stdout, indent=1, default=str)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
