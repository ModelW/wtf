"""Django touchpoint introspection, executed *inside the project's interpreter*.

Same contract as ``django_models.py``: stdlib-only, Python >= 3.10, piped on
stdin to the unit's Python, one JSON document on stdout, the project's own
logging redirected to stderr.

A *touchpoint* is an entry point through which data flows into or out of
the unit: an HTTP route, a background task, an admin screen. This script
inventories them from the running configuration, not from source text:

* **routes** from ``ROOT_URLCONF`` resolved recursively; id = the route
  name when the framework gives one (``orders:detail``), else
  ``METHOD /path``. Views mounted by Django Ninja are matched to the API's
  own OpenAPI document, which yields the operation id, request/response
  schemas (flattened to leaf ``name: type`` pairs) and security; DRF views
  expose their serializer classes the same way when installed.
* **tasks** registered with Procrastinate (``app.tasks``) or Celery
  (``app.tasks``): signature with annotations, ``periodic`` flag, and the
  tasks they defer (AST scan of the body for ``.defer(`` / ``.delay(`` /
  ``.configure(``).
* **admin** screens: one per registered ``ModelAdmin`` with its list /
  search / readonly fields — that is where staff actually read personal
  data.

Output schema (``schema: 1``)::

    {"schema": 1, "touchpoints": [
      {"id": "orders:checkout", "kind": "route", "path": "back/api/orders/checkout",
       "methods": ["POST"], "view": "fah.apps.orders.api.checkout",
       "file": "/repo/fah/apps/orders/api.py", "line": 115,
       "framework": "ninja", "operation_id": "checkout",
       "auth": ["SessionAuth"],
       "request": {"cart_id": "string(uuid)", "address_id": "string(uuid)"},
       "response": {"order_id": "string(uuid)", ...},
       "params": ["slug"]},
      {"id": "task:cart.delete_unused_anonymous_carts", "kind": "task", ...},
      {"id": "admin:orders.Order", "kind": "admin", ...}]}
"""

from __future__ import annotations

import ast
import contextlib
import inspect
import json
import os
import re
import sys

SCHEMA = 1
MAX_SCHEMA_LEAVES = 80


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _source(obj):
    """``(file, line)`` of a callable/class, ``(None, None)`` when unknown."""
    try:
        target = inspect.unwrap(obj)
    except ValueError:
        target = obj
    try:
        file = inspect.getsourcefile(target)
        line = inspect.getsourcelines(target)[1]
    except (TypeError, OSError):
        return None, None
    return file, line


def _dotted(obj):
    module = getattr(obj, "__module__", None) or ""
    name = getattr(obj, "__qualname__", None) or getattr(obj, "__name__", "") or ""
    return f"{module}.{name}".strip(".")


def _flatten_schema(schema, components, prefix="", depth=0, out=None, seen=None):
    """OpenAPI schema object → ``{dotted.leaf: type}`` (arrays as ``[]``)."""
    out = {} if out is None else out
    seen = set() if seen is None else seen
    if len(out) >= MAX_SCHEMA_LEAVES or depth > 6 or not isinstance(schema, dict):
        return out
    ref = schema.get("$ref")
    if ref:
        name = ref.rsplit("/", 1)[-1]
        if name in seen:
            out[prefix or name] = f"ref:{name}"
            return out
        seen = seen | {name}
        return _flatten_schema(
            components.get(name, {}), components, prefix, depth, out, seen
        )
    for key in ("anyOf", "oneOf", "allOf"):
        if key in schema:
            for alt in schema[key]:
                if alt.get("type") == "null":
                    continue
                _flatten_schema(alt, components, prefix, depth, out, seen)
            return out
    kind = schema.get("type")
    if kind == "object" or "properties" in schema:
        props = schema.get("properties") or {}
        if not props:
            out[prefix or "<object>"] = (
                "object(free-form)"
                if schema.get("additionalProperties", True)
                else "object"
            )
            return out
        for name, sub in props.items():
            _flatten_schema(
                sub,
                components,
                f"{prefix}.{name}" if prefix else name,
                depth + 1,
                out,
                seen,
            )
        return out
    if kind == "array":
        return _flatten_schema(
            schema.get("items", {}), components, f"{prefix}[]", depth + 1, out, seen
        )
    fmt = schema.get("format")
    label = kind or "any"
    if fmt:
        label = f"{label}({fmt})"
    if schema.get("enum"):
        label = f"{label} enum"
    out[prefix or "<value>"] = label
    return out


# --------------------------------------------------------------------------
# routes
# --------------------------------------------------------------------------


def _walk(patterns, prefix="", namespace=None):
    """Yield ``(path, name, pattern)`` for every leaf URL pattern."""
    for p in patterns:
        text = prefix + str(p.pattern)
        if hasattr(p, "url_patterns"):
            ns = p.namespace or namespace
            yield from _walk(p.url_patterns, text, ns)
        else:
            name = p.name
            if name and namespace:
                name = f"{namespace}:{name}"
            yield text, name, p


def _ninja_index():
    """``{(prefix+path, method): operation facts}`` for every NinjaAPI found.

    NinjaAPI instances are located through their mounted URL patterns: the
    ``PathView`` bound in the closure of each generated view keeps a
    reference to its ``api``.
    """
    try:
        from ninja import NinjaAPI  # noqa: F401
    except ImportError:
        return {}, set()
    from django.urls import get_resolver

    apis = {}
    for _text, _name, p in _walk(get_resolver().url_patterns):
        cb = p.callback
        for cell in getattr(cb, "__closure__", None) or ():
            pv = cell.cell_contents
            if type(pv).__name__ != "PathView":
                continue
            for op in getattr(pv, "operations", []):
                api = getattr(op, "api", None)
                if api is not None:
                    apis[id(api)] = api
    index = {}
    for api in apis.values():
        try:
            doc = api.get_openapi_schema()
        except Exception:
            continue
        components = (doc.get("components") or {}).get("schemas") or {}
        for path, ops in (doc.get("paths") or {}).items():
            for method, op in ops.items():
                if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                    continue
                request = {}
                body = ((op.get("requestBody") or {}).get("content") or {}).get(
                    "application/json", {}
                )
                if body.get("schema"):
                    request = _flatten_schema(body["schema"], components)
                params = []
                for param in op.get("parameters") or []:
                    where = param.get("in")
                    params.append(f"{where}:{param.get('name')}")
                    marker = "?" if where == "query" else "{}"
                    request.setdefault(
                        f"{marker}{param.get('name')}",
                        (param.get("schema") or {}).get("type", "any"),
                    )
                response = {}
                for code, resp in (op.get("responses") or {}).items():
                    if not str(code).startswith("2"):
                        continue
                    content = (resp.get("content") or {}).get("application/json", {})
                    if content.get("schema"):
                        response = _flatten_schema(content["schema"], components)
                        break
                auth = sorted({k for sec in op.get("security") or [] for k in sec})
                # Paths in the document carry the mount prefix, like the
                # resolved URL patterns do.
                index[(_normalise_path(path), method.upper())] = {
                    "framework": "ninja",
                    "operation_id": op.get("operationId"),
                    "request": request,
                    "response": response,
                    "params": params,
                    "auth": auth,
                    "summary": op.get("summary"),
                }
    return index, set(apis)


def _ninja_view(p):
    """The user's endpoint functions behind a Ninja-generated view."""
    for cell in getattr(p.callback, "__closure__", None) or ():
        pv = cell.cell_contents
        if type(pv).__name__ == "PathView":
            return {op.methods[0] if op.methods else "GET": op for op in pv.operations}
    return None


def _drf_facts(view_class):
    """Serializer fields of a DRF view, when DRF is installed and applicable."""
    try:
        from rest_framework.views import APIView
    except ImportError:
        return None
    if not (inspect.isclass(view_class) and issubclass(view_class, APIView)):
        return None
    facts = {"framework": "drf"}
    ser = getattr(view_class, "serializer_class", None)
    if ser is not None:
        try:
            fields = ser().get_fields()
            facts["request"] = {
                name: type(f).__name__ for name, f in fields.items() if not f.read_only
            }
            facts["response"] = {
                name: type(f).__name__ for name, f in fields.items() if not f.write_only
            }
        except Exception:
            facts["request"] = {"<serializer>": _dotted(ser)}
    perms = getattr(view_class, "permission_classes", None) or []
    facts["auth"] = [getattr(c, "__name__", str(c)) for c in perms]
    return facts


def _form_fields(view_class):
    """Fields of a Django ``FormView``-like class, if it declares a form."""
    form = getattr(view_class, "form_class", None)
    if form is None:
        return None
    try:
        return {name: type(f).__name__ for name, f in form.base_fields.items()}
    except Exception:
        return None


def _path_params(text):
    return re.findall(r"<(?:[^:>]+:)?([^>]+)>|\(\?P<(\w+)>", text)


def _normalise_path(text):
    """``api/x/<int:pk>/`` and ``/api/x/{pk}/`` → ``api/x/{pk}``."""
    text = re.sub(r"<(?:[^:>]+:)?([^>]+)>", r"{\1}", str(text))
    return text.strip("/")


def _route_touchpoints():
    from django.conf import settings
    from django.urls import get_resolver

    if not getattr(settings, "ROOT_URLCONF", None):
        return []
    ninja, _ = _ninja_index()
    out = []
    for text, name, p in _walk(get_resolver().url_patterns):
        cb = p.callback
        view_class = getattr(cb, "view_class", None) or getattr(cb, "cls", None)
        target = view_class or cb
        file, line = _source(target)
        ops = _ninja_view(p)
        if ops:
            # One touchpoint per method: Ninja's route name is per PathView,
            # the operation id is the stable, per-method identity.
            for method, op in ops.items():
                facts = ninja.get((_normalise_path(text), method), {})
                fn = op.view_func
                f_file, f_line = _source(fn)
                op_id = facts.get("operation_id") or getattr(op, "operation_id", None)
                # Id = the operation id (what generated clients call), under
                # the API's namespace only when it is not the default ``api``
                # — the unit prefix already says which service this is.
                namespace = name.rsplit(":", 1)[0] if name and ":" in name else "api"
                prefix = "" if namespace == "api" else f"{namespace}:"
                out.append(
                    {
                        "id": f"{prefix}{op_id}" if op_id else f"{method} /{text}",
                        "kind": "route",
                        "path": text,
                        "route_name": name,
                        "methods": [method],
                        "view": _dotted(fn),
                        "file": f_file,
                        "line": f_line,
                        "framework": "ninja",
                        "operation_id": op_id,
                        "auth": facts.get("auth")
                        or [
                            type(a).__name__ for a in getattr(op, "auth_callbacks", [])
                        ],
                        "request": facts.get("request", {}),
                        "response": facts.get("response", {}),
                        "params": facts.get("params", []),
                        "summary": facts.get("summary"),
                        "defers": _defers(fn),
                        "hints": _method_hints([method]) + _body_hints(fn),
                    }
                )
            continue
        methods = []
        if view_class is not None:
            methods = [
                m.upper()
                for m in getattr(view_class, "http_method_names", [])
                if hasattr(view_class, m) and m not in ("options", "head", "trace")
            ]
        facts = _drf_facts(view_class) or {}
        form = _form_fields(view_class) if view_class else None
        params = [a or b for a, b in _path_params(str(p.pattern))]
        out.append(
            {
                "id": name or f"ANY /{text}",
                "kind": "route",
                "path": text,
                "route_name": name,
                "methods": methods,
                "view": _dotted(target),
                "file": file,
                "line": line,
                "framework": facts.get("framework") or ("form" if form else "django"),
                "operation_id": None,
                "auth": facts.get("auth", []),
                "request": facts.get("request") or form or {},
                "response": facts.get("response", {}),
                "params": params,
                "summary": None,
                "defers": _defers(target),
                "hints": _method_hints(methods) + _body_hints(target),
            }
        )
    return out


# --------------------------------------------------------------------------
# tasks
# --------------------------------------------------------------------------

DEFER_CALL = re.compile(r"\.(defer|delay|apply_async|configure)\s*\(")


def _defers(func):
    """Names of tasks a function defers, from an AST scan of its body."""
    try:
        src = inspect.getsource(inspect.unwrap(func))
    except (OSError, TypeError):
        return []
    try:
        tree = ast.parse(inspect.cleandoc(src) if src[:1].isspace() else src)
    except SyntaxError:
        return []
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("defer", "delay", "apply_async", "configure"):
                owner = node.func.value
                while isinstance(owner, ast.Call) and isinstance(
                    owner.func, ast.Attribute
                ):
                    owner = owner.func.value
                names.append(ast.unparse(owner))
    return sorted(set(names))


# --------------------------------------------------------------------------
# op hints: what the body looks like it does, for the reviewer to confirm
# --------------------------------------------------------------------------

TASK_NAME_HINTS = (
    (re.compile(r"purge|clean|expire|prune|retention", re.I), "retention_purge"),
    (re.compile(r"anonymi[sz]e|erase|forget|gdpr", re.I), "erase"),
    (re.compile(r"export|portab|download_data|takeout", re.I), "portability"),
    (re.compile(r"delete|remove", re.I), "delete"),
)


def _body_hints(func):
    """Likely ops from the source of ``func``: ``.delete()``, ``timedelta``...

    These are *hints*: the reviewer confirms them against the code. The
    ``timedelta(days=30)`` value is reported so a ``retention_purge.after``
    can be pre-filled.
    """
    try:
        src = inspect.getsource(inspect.unwrap(func))
    except (OSError, TypeError):
        return []
    try:
        tree = ast.parse(inspect.cleandoc(src) if src[:1].isspace() else src)
    except SyntaxError:
        return []
    hints = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = node.func
        name = (
            callee.attr
            if isinstance(callee, ast.Attribute)
            else callee.id
            if isinstance(callee, ast.Name)
            else ""
        )
        if name == "delete":
            hints.append("delete: `.delete()` called")
        elif name in ("update", "bulk_update"):
            hints.append("update: `.update()` called")
        elif name in ("create", "get_or_create", "bulk_create", "save"):
            hints.append("create: `.create()`/`.save()` called")
        elif name in ("timedelta", "relativedelta"):
            hints.append(f"after: `{ast.unparse(node)}`")
        elif re.search(r"anonymi[sz]e|scrub|redact|forget", name, re.I):
            hints.append(f"erase: `{name}()` called (anonymise?)")
    return sorted(set(hints))


def _method_hints(methods):
    out = []
    if "POST" in methods:
        out.append("create: POST")
    if "PUT" in methods or "PATCH" in methods:
        out.append("update|rectify: PUT/PATCH")
    if "DELETE" in methods:
        out.append("delete|erase: DELETE")
    return out


def _task_name_hints(name):
    return [f"{op}: task name" for rx, op in TASK_NAME_HINTS if rx.search(name)]


def _admin_hints(model_admin):
    """What the admin screen lets staff do: add / change / delete / read only."""
    hints = []
    for perm, op in (
        ("has_add_permission", "create"),
        ("has_change_permission", "rectify(by=staff)|update"),
        ("has_delete_permission", "erase(by=staff)|delete"),
    ):
        method = getattr(type(model_admin), perm, None)
        overridden = method is not None and perm in vars(type(model_admin))
        if overridden:
            src = ""
            with contextlib.suppress(OSError, TypeError):
                src = inspect.getsource(method)
            if re.search(r"return\s+False", src):
                hints.append(f"no {op}: {perm} returns False")
                continue
        hints.append(f"{op}: {perm} default (allowed)")
    readonly = list(getattr(model_admin, "readonly_fields", None) or ())
    if readonly:
        hints.append("read only: " + ", ".join(str(f) for f in readonly))
    if getattr(model_admin, "list_display", None):
        hints.append("read: list_display")
    return hints


def _signature(func):
    try:
        sig = inspect.signature(inspect.unwrap(func))
    except (TypeError, ValueError):
        return {}
    out = {}
    for name, param in sig.parameters.items():
        if name in ("self", "cls", "context", "timestamp"):
            continue
        ann = param.annotation
        out[name] = (
            "any"
            if ann is inspect.Parameter.empty
            else getattr(ann, "__name__", None) or str(ann)
        )
    return out


def _task_touchpoints():
    out = []
    try:
        from procrastinate.contrib.django import app as pro_app

        tasks = dict(pro_app.tasks)
    except Exception:
        tasks = {}
    periodic = set()
    with contextlib.suppress(Exception):
        periodic = {
            key[0] if isinstance(key, tuple) else key
            for key in pro_app.periodic_registry.periodic_tasks
        }
    for name, task in tasks.items():
        if name.startswith("builtin:") or name.startswith("procrastinate."):
            continue
        file, line = _source(task.func)
        out.append(
            {
                "id": f"task:{name}",
                "kind": "task",
                "framework": "procrastinate",
                "view": _dotted(task.func),
                "file": file,
                "line": line,
                "periodic": name in periodic,
                "request": _signature(task.func),
                "defers": _defers(task.func),
                "queue": getattr(task, "queue", None),
                "hints": _task_name_hints(name) + _body_hints(task.func),
            }
        )
    try:
        from celery import current_app

        for name, task in current_app.tasks.items():
            if name.startswith("celery."):
                continue
            func = getattr(task, "run", task)
            file, line = _source(func)
            out.append(
                {
                    "id": f"task:{name}",
                    "kind": "task",
                    "framework": "celery",
                    "view": _dotted(func),
                    "file": file,
                    "line": line,
                    "periodic": False,
                    "request": _signature(func),
                    "defers": _defers(func),
                    "queue": getattr(task, "queue", None),
                    "hints": _task_name_hints(name) + _body_hints(func),
                }
            )
    except Exception:
        pass
    return out


# --------------------------------------------------------------------------
# admin
# --------------------------------------------------------------------------


def _admin_touchpoints():
    try:
        from django.contrib import admin
    except ImportError:
        return []
    out = []
    for model, model_admin in admin.site._registry.items():
        label = f"{model._meta.app_label}.{model.__name__}"
        file, line = _source(type(model_admin))
        fields = {}
        for attr in ("list_display", "search_fields", "readonly_fields", "fields"):
            values = getattr(model_admin, attr, None) or ()
            for v in values:
                if isinstance(v, str):
                    fields.setdefault(v, attr)
        out.append(
            {
                "id": f"admin:{label}",
                "kind": "admin",
                "framework": "admin",
                "model": label,
                "view": _dotted(type(model_admin)),
                "file": file,
                "line": line,
                "request": fields,
                "inlines": [
                    f"{i.model._meta.app_label}.{i.model.__name__}"
                    for i in getattr(model_admin, "inlines", [])
                ],
                "hints": _admin_hints(model_admin),
            }
        )
    return out


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def main() -> int:
    """Set Django up and dump every touchpoint; return the exit status."""
    real_stdout = sys.stdout
    sys.stdout = sys.stderr
    try:
        import django

        django.setup()
        payload = {
            "schema": SCHEMA,
            "django": django.get_version(),
            "settings": os.environ.get("DJANGO_SETTINGS_MODULE"),
            "touchpoints": [
                *_route_touchpoints(),
                *_task_touchpoints(),
                *_admin_touchpoints(),
            ],
        }
    except Exception as exc:
        print(
            f"model-wtf touchpoint introspection failed: {type(exc).__name__}: {exc}",
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
