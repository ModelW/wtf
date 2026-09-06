"""Touchpoints: the entry points through which data flows in and out of a unit.

Vocabulary (kept clear of pytm's, which comes later): a **unit** is a
running component (a pytm *Process*); a **touchpoint** is one of its entry
points — an HTTP route, a background task, an admin screen, a SvelteKit
route — through which data flows (pytm *Dataflows*); an **activity** (see
:mod:`model_wtf.compliance.activities`) is a GDPR processing activity that
groups touchpoints under one purpose. The word "process" is not used here.

Like the data inventory, touchpoints are *virtual*: introspected from the
running configuration (Django URL resolver, Ninja's OpenAPI document,
Procrastinate/Celery registries, the admin site; SvelteKit's generated
``$types.d.ts`` resolved with the project's TypeScript) and never written
to disk. What humans (or the agent) write is the optional **manifest**
``<unit>/compliance/touchpoints/<slug>.yaml``::

    data:                       # data items the touchpoint reads or writes
      - api:orders.Order.customer_email
      - api:orders.Order.payload@json.iban
    direction: {api:orders.Order.customer_email: write}   # optional
    ignore: false               # health checks, static assets

A touchpoint is **pending** until its manifest has a ``data`` key; an
explicit empty list means "touches nothing personal, checked" and is a
valid review. Data references must exist in the inventory of the named
unit; unknown ones are declaration errors.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from model_wtf.compliance.declarations import format_errors
from model_wtf.compliance.report import Diagnostic, Severity
from model_wtf.compliance.schemas import StrictModel
from model_wtf.compliance.yaml_io import load_yaml
from model_wtf.introspect.runner import (
    IntrospectionFailed,
    IntrospectionUnavailable,
    is_django_unit,
    run_django_script,
    run_node_script,
)

if TYPE_CHECKING:
    from model_wtf.compliance.data import Row
    from model_wtf.compliance.report import Unit

TOUCHPOINTS_DIR = "touchpoints"
SCHEMA = 1
IGNORED_BY_DEFAULT = (
    re.compile(r"^whealth_"),
    re.compile(r"^(\w+:)?(openapi|openapi-json|openapi-view|openapi-schema|api-root)$"),
    # Django admin URL patterns: the per-model ``admin:<app.Model>`` screen
    # touchpoint is the one that means something; the routes behind it
    # (changelist, add, change, history, jsi18n...) are plumbing.
    re.compile(r"^admin:[a-z_]+$"),  # admin:index, admin:login, admin:jsi18n...
    re.compile(r"^admin:\w+_\w+_(changelist|add|change|delete|history)$"),
    re.compile(r"^ANY /(?:[^ ]*/)?admin/"),
    re.compile(r"^wagtailadmin_(sprite|javascript_catalog|api:|icons)"),
    re.compile(r"^wagtailadmin_(home|dashboard|login|logout|account|userbar)"),
    re.compile(r"^django\.views\.static\.serve$"),
    re.compile(r"^ANY /[^ ]*\$$"),  # regex catch-alls (admin app index, wagtail)
)
"""Touchpoints that are plumbing by construction (health checks, schema
documents, static assets, the admin's own URL patterns): hidden unless a
manifest says otherwise. The admin's data exposure is carried by the
``admin:<app.Model>`` screen touchpoints instead."""


class Kind(StrEnum):
    """What sort of entry point a touchpoint is."""

    ROUTE = "route"
    TASK = "task"
    ADMIN = "admin"


class Manifest(StrictModel):
    """``touchpoints/<slug>.yaml``."""

    data: list[str] | None = None
    direction: dict[str, Literal["read", "write", "read+write"]] = Field(
        default_factory=dict
    )
    ignore: bool = False
    note: str | None = None


class Introspected(BaseModel):
    """One touchpoint as reported by an introspection script (either unit type)."""

    model_config = ConfigDict(extra="ignore")

    id: str
    kind: Kind = Kind.ROUTE
    framework: str = ""
    path: str | None = None
    route_name: str | None = None
    methods: list[str] = Field(default_factory=list)
    view: str | None = None
    file: str | None = None
    line: int | None = None
    operation_id: str | None = None
    auth: list[str] = Field(default_factory=list)
    request: dict[str, str] = Field(default_factory=dict)
    response: dict[str, str] = Field(default_factory=dict)
    params: list[str] = Field(default_factory=list)
    summary: str | None = None
    # tasks
    periodic: bool = False
    defers: list[str] = Field(default_factory=list)
    queue: str | None = None
    # admin
    model: str | None = None
    inlines: list[str] = Field(default_factory=list)
    # sveltekit
    files: list[str] = Field(default_factory=list)
    handlers: list[str] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)
    data: dict[str, str] = Field(default_factory=dict)
    action_data: dict[str, str] = Field(default_factory=dict)
    form_fields: list[str] = Field(default_factory=list)
    calls: list[str] = Field(default_factory=list)
    fetches: list[str] = Field(default_factory=list)
    layout_only: bool = False


class Payload(BaseModel):
    """Whole script output."""

    model_config = ConfigDict(extra="ignore")

    schema_version: int = Field(alias="schema")
    touchpoints: list[Introspected] = Field(default_factory=list)


@dataclass(frozen=True)
class Touchpoint:
    """One touchpoint with its manifest applied."""

    unit: str
    facts: Introspected
    data: tuple[str, ...] | None = None
    """``unit:id`` data references; ``None`` = no manifest yet (pending)."""
    direction: dict[str, str] = field(default_factory=dict)
    ignore: bool = False
    note: str | None = None
    calls: tuple[str, ...] = ()
    """Full ids of the touchpoints this one calls (cross-unit edges)."""
    code_root: Path | None = None
    """Where the unit's code lives, to resolve relative file paths."""

    @property
    def id(self) -> str:
        """Stable id within the unit (route name, ``task:...``, route ID)."""
        return self.facts.id

    @property
    def full_id(self) -> str:
        """``unit:id``."""
        return f"{self.unit}:{self.id}"

    @property
    def slug(self) -> str:
        """File stem of the manifest: the id with path separators made safe."""
        return slugify(self.id)

    @property
    def pending(self) -> bool:
        """Whether it still needs a data declaration."""
        return self.data is None and not self.ignore

    @property
    def fingerprint(self) -> str:
        """Hash of the facts a review looked at (schemas, view, methods)."""
        f = self.facts
        text = "|".join(
            [
                f.id,
                f.kind.value,
                f.view or "",
                ",".join(sorted(f.methods)),
                ",".join(sorted(f.request)),
                ",".join(sorted(f.response)),
                ",".join(sorted(f.data)),
                ",".join(sorted(f.form_fields)),
                ",".join(sorted(f.calls)),
                ",".join(sorted(f.auth)),
            ]
        )
        return hashlib.sha256(text.encode()).hexdigest()[:8]

    def location(self, root: Path) -> str | None:
        """``file:line`` relative to the repository, if known.

        Django reports absolute paths; the SvelteKit script reports paths
        relative to the unit, which :attr:`code_root` makes absolute.
        """
        if not self.facts.file:
            return None
        path = Path(self.facts.file)
        if not path.is_absolute() and self.code_root is not None:
            path = self.code_root / path
        try:
            shown = str(path.resolve().relative_to(root.resolve()))
        except ValueError:
            shown = str(path)
        return f"{shown}:{self.facts.line}" if self.facts.line else shown

    def to_dict(self, root: Path | None = None) -> dict[str, Any]:
        """JSON form."""
        return {
            "unit": self.unit,
            "id": self.id,
            "kind": self.facts.kind.value,
            "framework": self.facts.framework,
            "path": self.facts.path,
            "methods": self.facts.methods,
            "view": self.facts.view,
            "location": self.location(root) if root else self.facts.file,
            "auth": self.facts.auth,
            "request": self.facts.request,
            "response": self.facts.response,
            "params": self.facts.params,
            "periodic": self.facts.periodic,
            "defers": self.facts.defers,
            "model": self.facts.model,
            "files": self.facts.files,
            "actions": self.facts.actions,
            "handlers": self.facts.handlers,
            "page_data": self.facts.data,
            "form_fields": self.facts.form_fields,
            "calls": list(self.calls),
            "fetches": self.facts.fetches,
            "data": list(self.data) if self.data is not None else None,
            "direction": dict(self.direction),
            "ignore": self.ignore,
            "pending": self.pending,
            "note": self.note,
            "fingerprint": self.fingerprint,
        }


@dataclass
class UnitTouchpoints:
    """Everything computed for one unit."""

    unit: Unit
    items: list[Touchpoint] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    introspected: bool = False

    def get(self, touchpoint_id: str) -> Touchpoint | None:
        """Lookup by local id."""
        return next((t for t in self.items if t.id == touchpoint_id), None)

    def visible(self) -> list[Touchpoint]:
        """Items not hidden by ``ignore``."""
        return [t for t in self.items if not t.ignore]


def slugify(touchpoint_id: str) -> str:
    """Manifest file stem for a touchpoint id.

    ``/kitchen/[restaurant_uuid]`` → ``kitchen__[restaurant_uuid]``,
    ``admin:orders.Order`` → ``admin__orders.Order``, ``/`` → ``__root__``:
    ``/`` and ``:`` are the two characters a filesystem may refuse.
    """
    if touchpoint_id == "/":
        return "__root__"
    return touchpoint_id.strip("/").replace("/", "__").replace(":", "__")


def _matches_manifest(touchpoint_id: str, stem: str) -> bool:
    return slugify(touchpoint_id) == stem


def collect_touchpoints(
    unit: Unit,
    *,
    python: str | None = None,
    known_data: dict[str, set[str]] | None = None,
) -> UnitTouchpoints:
    """Introspect ``unit`` and apply its manifests.

    ``known_data`` maps unit id → set of data item ids, used to validate the
    references manifests make (``store-unknown``-style errors). Pass
    ``None`` to skip that validation.
    """
    result = UnitTouchpoints(unit)
    facts = _introspect(unit, result.diagnostics, python=python)
    result.introspected = facts is not None
    manifests = _load_manifests(unit, result.diagnostics)
    used: set[str] = set()
    for item in facts or []:
        stem = slugify(item.id)
        manifest = manifests.get(stem)
        if manifest is not None:
            used.add(stem)
        result.items.append(
            _apply(unit, item, manifest, known_data, result.diagnostics)
        )
    for stem in sorted(set(manifests) - used):
        result.diagnostics.append(
            Diagnostic(
                Severity.ERROR,
                "touchpoint-orphan-manifest",
                f"{stem}.yaml: no touchpoint {stem!r} in unit {unit.id}",
                unit.id,
                unit.folder / TOUCHPOINTS_DIR / f"{stem}.yaml",
            )
        )
    result.items.sort(key=lambda t: (t.facts.kind.value, t.id))
    return result


def link_calls(all_units: dict[str, UnitTouchpoints]) -> None:
    """Resolve SvelteKit ``calls`` (operation ids) to Django touchpoints.

    Rewrites each front touchpoint's ``calls`` to full ids of the api
    touchpoints whose ``operation_id`` matches; unknown operation ids are
    kept verbatim so they still show up.
    """
    by_operation: dict[str, str] = {}
    for unit_tps in all_units.values():
        for tp in unit_tps.items:
            if tp.facts.operation_id:
                # Generated clients camelise operation ids (``kitchen_orders``
                # -> ``kitchenOrders``); index both spellings.
                by_operation[tp.facts.operation_id] = tp.full_id
                by_operation[_camel(tp.facts.operation_id)] = tp.full_id
    for unit_tps in all_units.values():
        for index, tp in enumerate(unit_tps.items):
            if not tp.facts.calls:
                continue
            resolved = tuple(by_operation.get(c, c) for c in tp.facts.calls)
            unit_tps.items[index] = replace(tp, calls=resolved)


def _camel(snake: str) -> str:
    head, *rest = snake.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in rest)


def _introspect(
    unit: Unit, diagnostics: list[Diagnostic], *, python: str | None
) -> list[Introspected] | None:
    code_root = unit.code_root or unit.folder.parent
    discover = unit.discover
    if discover == "none" and is_django_unit(code_root):
        discover = "django"
    try:
        if discover == "django":
            raw = run_django_script(code_root, "django_touchpoints.py", python=python)
        elif discover == "sveltekit" and (code_root / "package.json").is_file():
            raw = run_node_script(code_root, "sveltekit_touchpoints.mjs")
        else:
            # No code to look at (or an engine we do not know): nothing to
            # say, exactly like the data inventory of a non-Django unit.
            return None
    except IntrospectionUnavailable as exc:
        diagnostics.append(
            Diagnostic(
                Severity.WARNING, "not-introspectable", str(exc), unit.id, code_root
            )
        )
        return None
    try:
        payload = Payload.model_validate(raw)
    except ValidationError as exc:
        msg = f"touchpoint introspection of {code_root}: invalid payload: {exc}"
        raise IntrospectionFailed(msg) from exc
    if payload.schema_version != SCHEMA:
        msg = f"unsupported touchpoint schema {payload.schema_version}"
        raise IntrospectionFailed(msg)
    return payload.touchpoints


def _apply(
    unit: Unit,
    facts: Introspected,
    manifest: Manifest | None,
    known_data: dict[str, set[str]] | None,
    diagnostics: list[Diagnostic],
) -> Touchpoint:
    ignored_by_default = any(p.search(facts.id) for p in IGNORED_BY_DEFAULT)
    if manifest is None:
        return Touchpoint(
            unit=unit.id,
            facts=facts,
            ignore=ignored_by_default,
            calls=tuple(facts.calls),
        )
    path = unit.folder / TOUCHPOINTS_DIR / f"{slugify(facts.id)}.yaml"
    data: tuple[str, ...] | None = None
    if manifest.data is not None:
        refs = []
        for ref in manifest.data:
            full = ref if ":" in ref else f"{unit.id}:{ref}"
            ref_unit, _, ref_id = full.partition(":")
            if known_data is not None:
                if ref_unit not in known_data:
                    diagnostics.append(
                        Diagnostic(
                            Severity.ERROR,
                            "data-ref-unknown-unit",
                            f"{path.name}: {ref!r} names unknown unit {ref_unit!r}",
                            unit.id,
                            path,
                        )
                    )
                    continue
                if ref_id not in known_data[ref_unit]:
                    diagnostics.append(
                        Diagnostic(
                            Severity.ERROR,
                            "data-ref-unknown",
                            f"{path.name}: no data item {full!r} "
                            "(`data list` shows the ids)",
                            unit.id,
                            path,
                        )
                    )
                    continue
            refs.append(full)
        data = tuple(refs)
    direction: dict[str, str] = {
        (k if ":" in k else f"{unit.id}:{k}"): str(v)
        for k, v in manifest.direction.items()
    }
    return Touchpoint(
        unit=unit.id,
        facts=facts,
        data=data,
        direction=direction,
        ignore=manifest.ignore,
        note=manifest.note,
        calls=tuple(facts.calls),
        code_root=unit.code_root,
    )


def _load_manifests(unit: Unit, diagnostics: list[Diagnostic]) -> dict[str, Manifest]:
    folder = unit.folder / TOUCHPOINTS_DIR
    out: dict[str, Manifest] = {}
    if not folder.is_dir():
        return out
    for path in sorted(folder.glob("*.yaml")):
        try:
            raw = load_yaml(path)
        except (OSError, yaml.YAMLError) as exc:
            diagnostics.append(
                Diagnostic(
                    Severity.ERROR, "yaml-error", f"{path.name}: {exc}", unit.id, path
                )
            )
            continue
        if not isinstance(raw, dict):
            diagnostics.append(
                Diagnostic(
                    Severity.ERROR,
                    "schema-error",
                    f"{path.name}: expected a mapping",
                    unit.id,
                    path,
                )
            )
            continue
        try:
            out[path.stem] = Manifest.model_validate(raw)
        except ValidationError as exc:
            diagnostics.extend(
                Diagnostic(
                    Severity.ERROR,
                    "schema-error",
                    f"{path.name}: {loc}: {msg}",
                    unit.id,
                    path,
                )
                for loc, msg in format_errors(exc)
            )
    return out


def write_manifest(
    unit: Unit,
    touchpoint: Touchpoint,
    data: list[str],
    *,
    direction: dict[str, str] | None = None,
    note: str | None = None,
    ignore: bool = False,
) -> Path:
    """Create or replace the manifest of ``touchpoint``; return its path."""
    path = unit.folder / TOUCHPOINTS_DIR / f"{touchpoint.slug}.yaml"
    lines: list[str] = []
    if ignore:
        lines.append("ignore: true")
    lines.append("data:" if data else "data: []")
    lines.extend(f"  - {ref}" for ref in data)
    if direction:
        lines.append("direction:")
        lines.extend(f"  {ref}: {value}" for ref, value in direction.items())
    if note:
        lines.append(f"note: {_scalar(note)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _scalar(value: str) -> str:
    """One YAML scalar, quoted only when needed (no document markers)."""
    return (
        yaml.safe_dump(value, default_style=None, width=10**6)
        .strip()
        .removesuffix("\n...")
    )


def data_index(rows_by_unit: dict[str, list[Row]]) -> dict[str, set[str]]:
    """``{unit: {item ids}}`` from collected data rows, for reference checks."""
    return {unit: {r.id for r in rows} for unit, rows in rows_by_unit.items()}
