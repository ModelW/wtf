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

    data:                       # data items and what the code does to them
      - api:orders.Order.customer_email: create  # `ref: <op>`, `ref: [ops]`,
      - api:people.User.email: {rectify: {by: subject}}   # or with metadata
      - api:people.User.*: {erase: {by: subject}}         # globs for whole models
      - api:orders.Order.payload@json.iban       # a bare ref = read
    transfers:                  # what leaves to another organisation
      - party: mapbox           # id in compliance/parties/
        data: [api:geo.Address.position]
        purpose: geocoding      # optional, one line
    ignore: false               # health checks, static assets

The operations vocabulary lives in :mod:`model_wtf.compliance.ops`. Each
ref carries what this touchpoint *does* to the item (``create``, ``read``,
``rectify``, ``erase``, ``retention_purge``, ...); the rights derivation
reads them, the touchpoint only states facts. ``write`` is a deprecated
alias for ``[create, update]`` and warns.

``transfers`` (GDPR wording, Ch. V / Art. 4(9); ``exporting`` is accepted
with a deprecation warning) is where the Art. 30 "recipients" column comes
from: every call to an external API, every email provider, every analytics
beacon is a transfer of the listed items to that party. The party must exist
in ``compliance/parties/`` (the agent creates it with ``!todo`` details when
it meets a new one); its ``country`` drives the third-country logic.

A touchpoint is **pending** until its manifest has a ``data`` key; the list
names every inventory item the code reads or writes, personal or not (the
register filters on ``pii`` downstream; the data-flow model needs all of
it). An explicit empty list means "touches no inventory item, checked" and
is a valid review. Data references must exist in the inventory of the named
unit; unknown ones are declaration errors.
"""

from __future__ import annotations

import hashlib
import io
import re
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from fnmatch import fnmatchcase
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from ruamel.yaml import YAML as RuamelYAML

from model_wtf.compliance.declarations import format_errors
from model_wtf.compliance.ops import OpError, OpSpec, Read, parse_ops, render_ops
from model_wtf.compliance.report import Diagnostic, Severity
from model_wtf.compliance.schemas import StrictModel
from model_wtf.compliance.stamps import Stamps, read_stamps, stamp_lines
from model_wtf.compliance.yaml_io import load_yaml
from model_wtf.introspect.runner import (
    IntrospectionFailed,
    IntrospectionUnavailable,
    is_django_unit,
    run_django_script,
    run_node_script,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

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
    re.compile(r"^admin:[a-z_0-9]+$"),  # admin:index, admin:login, admin:jsi18n...
    re.compile(r"test404|/__debug__/|^djdt:"),
    re.compile(r"^admin:\w+_\w+_(changelist|add|change|delete|history)$"),
    re.compile(r"^ANY /(?:[^ ]*/)?admin/"),
    re.compile(r"^wagtailadmin_(sprite|javascript_catalog|api:|icons)"),
    # ``wagtailadmin_account`` (the staff member's own profile: avatar,
    # language, password) and ``logout`` are where a staff user exercises
    # rights on their own data: not plumbing.
    re.compile(r"^wagtailadmin_(home|dashboard|login|userbar)"),
    re.compile(r"^django\.views\.static\.serve$"),
    re.compile(r"^ANY /[^ ]*\$$"),  # regex catch-alls (admin app index, wagtail)
)
"""Touchpoints that are plumbing by construction (health checks, schema
documents, static assets, the admin's own URL patterns): hidden unless a
manifest says otherwise. The admin's data exposure is carried by the
``admin:<app.Model>`` screen touchpoints instead."""


_VENDOR_DIRS = re.compile(
    r"(^|/)(site-packages|dist-packages|node_modules|\.venv|venv)/"
)


def _is_vendor_path(path: str | None) -> bool:
    return bool(path) and bool(_VENDOR_DIRS.search(str(path).replace("\\", "/")))


class Kind(StrEnum):
    """What sort of entry point a touchpoint is."""

    ROUTE = "route"
    TASK = "task"
    ADMIN = "admin"


class Scope(StrEnum):
    """Who a touchpoint serves; the rights derivation reads ops through it.

    A ``read`` on a ``subject`` touchpoint is the person seeing their own
    data (Art. 15); the same ``read`` on a ``staff`` screen is not.
    """

    SUBJECT = "subject"
    """An authenticated end user acting on their own data (session/JWT auth,
    not the admin)."""

    STAFF = "staff"
    """Back-office: the admin, an ``IsAdminUser``/staff-only view."""

    PUBLIC = "public"
    """Anonymous callers: catalogue, signup, login, health."""

    SYSTEM = "system"
    """Nobody in particular: a task, a webhook, a cron."""


_STAFF_AUTH = re.compile(r"admin|staff|superuser", re.I)
_STAFF_ROUTE = re.compile(
    r"^(admin:|wagtail(admin|users|docs|images|embeds|forms|redirects|snippets|sites|"
    r"search|locales|core_)|wagtail_)"
)
"""Route-name namespaces that only exist inside a back-office (Django admin,
Wagtail admin and its apps' management views)."""
_USER_AUTH = re.compile(r"session|jwt|token|authenticated|login|bearer|user", re.I)


def infer_scope(facts: Introspected) -> Scope:
    """Best guess from kind and auth classes; a manifest ``scope`` overrides it.

    Heuristics only: DRF/Ninja auth class names are read for "staff"
    (``IsAdminUser``) and "user" (``SessionAuth``, ``IsAuthenticated``)
    markers; a route without any auth is public.
    """
    if facts.kind is Kind.TASK:
        return Scope.SYSTEM
    if facts.kind is Kind.ADMIN or _STAFF_ROUTE.match(facts.id):
        return Scope.STAFF
    if facts.file and "/wagtail/admin/" in facts.file.replace("\\", "/"):
        return Scope.STAFF
    auth = " ".join(facts.auth)
    body = " ".join(facts.hints)
    if _STAFF_AUTH.search(auth) or "scope staff" in body:
        return Scope.STAFF
    if _USER_AUTH.search(auth) or "scope subject" in body:
        return Scope.SUBJECT
    return Scope.PUBLIC


class Transfer(StrictModel):
    """One outbound flow: these items go to that party (another organisation)."""

    party: str
    data: list[str] = Field(default_factory=list)
    purpose: str | None = None


Export = Transfer
"""Former name, kept for callers."""

DataEntry = str | dict[str, Any]
"""One ``data`` entry: a bare ref (read) or ``{ref: <ops>}``."""


class Undeclared(StrictModel):
    """A flow a reviewer found in the code that the manifest does not declare:
    data going to a sink (usually a host or a service) nobody accounted for.

    Recorded by ``flow_report``; it is a finding (``flow-undeclared``) and
    makes the touchpoint pending: the declaration is incomplete until the
    transfer (and its party) are declared, or the code stops sending.
    """

    sink: str
    """Where it goes: ``party:<id>`` when the party exists, else the host or
    service name as seen in the code (``hooks.zapier.com``)."""
    data: list[str] = Field(default_factory=list)
    """Inventory refs of what is sent (resolved to full ids)."""
    note: str
    """The evidence: file:line and what the code does."""
    commit: str | None = None
    at: str | None = None


class ManifestChallenge(StrictModel):
    """See :class:`model_wtf.compliance.review.Challenge`."""

    commit: str
    grounds: str
    at: str | None = None


class Manifest(StrictModel):
    """``touchpoints/<slug>.yaml``."""

    data: list[DataEntry] | None = None
    transfers: list[Transfer] = Field(default_factory=list)
    exporting: list[Transfer] | None = Field(
        default=None, description="Deprecated spelling of `transfers`"
    )
    scope: Scope | None = Field(
        default=None,
        description="Who this touchpoint serves (subject | staff | public | "
        "system); inferred from auth when absent",
    )
    ignore: bool = False
    note: str | None = None
    challenge: ManifestChallenge | None = Field(
        default=None,
        description="A doubt cast by the challenger on this declaration; the "
        "touchpoint is pending until re-reviewed",
    )
    answered: ManifestChallenge | None = Field(
        default=None,
        description="The last challenge a re-review closed (kept so the same "
        "grounds are not raised twice)",
    )
    threats: Stamps = Field(
        default_factory=Stamps,
        description="Stamps closing the threat cells the matrix left open "
        "(`SID` or `SID@sink` -> {status, note} or !missing)",
    )
    undeclared: list[Undeclared] = Field(
        default_factory=list,
        description="Flows a reviewer found in the code that this manifest "
        "does not declare (see `flow_report`); each is a finding until the "
        "transfer is declared or the code stops sending",
    )

    @model_validator(mode="after")
    def _fold_exporting(self) -> Manifest:
        if self.exporting:
            self.transfers = [*self.transfers, *self.exporting]
        return self

    def entries(self) -> list[tuple[str, list[OpSpec], list[str]]]:
        """``(ref pattern, ops, warnings)`` per entry.

        Raises
        ------
        OpError
            With the ref in the message, when the ops do not parse.
        """
        out: list[tuple[str, list[OpSpec], list[str]]] = []
        for entry in self.data or []:
            if isinstance(entry, str):
                out.append((entry, [Read()], []))
                continue
            if len(entry) != 1:
                msg = f"a data entry is one `ref: ops` mapping, got {entry!r}"
                raise OpError(msg)
            ((ref, value),) = entry.items()
            try:
                ops, warnings = parse_ops(value)
            except OpError as exc:
                msg = f"{ref}: {exc}"
                raise OpError(msg) from exc
            out.append((str(ref), ops, warnings))
        return out


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
    hints: list[str] = Field(default_factory=list)
    """Likely ops seen by the introspection (``create: POST``, ``after:
    timedelta(days=30)``); the reviewer confirms, never copies blindly."""


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
    ops: dict[str, tuple[OpSpec, ...]] = field(default_factory=dict)
    """Per full ref, what this touchpoint does to it (globs expanded)."""
    transfers: tuple[Transfer, ...] = ()
    """Outbound flows to other organisations, refs resolved to full ids."""
    scope: Scope = Scope.PUBLIC
    """Who it serves (see :class:`Scope`); declared or inferred."""
    scope_declared: bool = False
    ignore: bool = False
    note: str | None = None
    challenge: ManifestChallenge | None = None
    """Open doubt on the declaration; makes the touchpoint pending."""
    answered: ManifestChallenge | None = None
    undeclared: tuple[Undeclared, ...] = ()
    """Flows found in the code and missing from the declaration."""
    stamps: Stamps = field(default_factory=Stamps)
    """Threat stamps declared in the manifest."""
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
        """Whether it still needs a data declaration (or a re-review after
        a challenge)."""
        if self.ignore:
            return False
        return self.data is None or self.challenge is not None or bool(self.undeclared)

    @property
    def vendor(self) -> bool:
        """Whether the code behind it is a dependency's (Django's, Wagtail's,
        a node package's), not the project's.

        Its controls are the framework's, kept by dependency updates and
        usually placed where a view-level read cannot see them (Wagtail
        wraps its admin URL conf in ``require_admin_access``); reviewing the
        view alone yields false findings. What stays ours: the data it
        exposes (the declaration) and the surface it sits on.
        """
        return _is_vendor_path(self.facts.file)

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

    @property
    def exporting(self) -> tuple[Transfer, ...]:
        """Former name of :attr:`transfers`."""
        return self.transfers

    def ops_of(self, ref: str) -> tuple[OpSpec, ...]:
        """The ops on one full ref (``read`` when the manifest is bare)."""
        return self.ops.get(ref, (Read(),) if self.data and ref in self.data else ())

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
            "hints": self.facts.hints,
            "data": list(self.data) if self.data is not None else None,
            "ops": {ref: [op.to_yaml() for op in ops] for ref, ops in self.ops.items()},
            "transfers": [e.model_dump() for e in self.transfers],
            "scope": self.scope.value,
            "ignore": self.ignore,
            "pending": self.pending,
            "vendor": self.vendor,
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
    known_parties: set[str] | None = None,
) -> UnitTouchpoints:
    """Introspect ``unit`` and apply its manifests.

    ``known_data`` maps unit id → set of data item ids and ``known_parties``
    is the set of party ids, both used to validate what manifests
    reference. Pass ``None`` to skip a validation.
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
            _apply(unit, item, manifest, known_data, result.diagnostics, known_parties)
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


def _resolve_refs(
    refs: list[str],
    unit: Unit,
    path: Path,
    known_data: dict[str, set[str]] | None,
    diagnostics: list[Diagnostic],
) -> list[str]:
    """``unit:id`` for every ref (unit defaults to this one); unknown ones dropped."""
    out: list[str] = []
    for ref in refs:
        out.extend(_resolve_one(ref, unit, path, known_data, diagnostics))
    return out


def _resolve_one(
    ref: str,
    unit: Unit,
    path: Path,
    known_data: dict[str, set[str]] | None,
    diagnostics: list[Diagnostic],
) -> list[str]:
    """One ref or glob → the full ids it names (validated when possible).

    A glob (``api:people.User.*``) expands against the inventory of its
    unit and must match at least one item; without an inventory to check
    against it is kept verbatim.
    """
    full = ref if ":" in ref else f"{unit.id}:{ref}"
    ref_unit, _, ref_id = full.partition(":")
    if known_data is None:
        return [full]
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
        return []
    if any(c in ref_id for c in "*?["):
        matched = sorted(i for i in known_data[ref_unit] if fnmatchcase(i, ref_id))
        if not matched:
            diagnostics.append(
                Diagnostic(
                    Severity.ERROR,
                    "data-ref-unknown",
                    f"{path.name}: {full!r} matches no data item",
                    unit.id,
                    path,
                )
            )
        return [f"{ref_unit}:{i}" for i in matched]
    if ref_id not in known_data[ref_unit]:
        diagnostics.append(
            Diagnostic(
                Severity.ERROR,
                "data-ref-unknown",
                f"{path.name}: no data item {full!r} (`data list` shows the ids)",
                unit.id,
                path,
            )
        )
        return []
    return [full]


def _apply(
    unit: Unit,
    facts: Introspected,
    manifest: Manifest | None,
    known_data: dict[str, set[str]] | None,
    diagnostics: list[Diagnostic],
    known_parties: set[str] | None = None,
) -> Touchpoint:
    ignored_by_default = any(p.search(facts.id) for p in IGNORED_BY_DEFAULT)
    if manifest is None:
        return Touchpoint(
            unit=unit.id,
            facts=facts,
            scope=infer_scope(facts),
            ignore=ignored_by_default,
            calls=tuple(facts.calls),
        )
    path = unit.folder / TOUCHPOINTS_DIR / f"{slugify(facts.id)}.yaml"
    data: tuple[str, ...] | None = None
    ops: dict[str, list[OpSpec]] = {}
    if manifest.data is not None:
        resolved: list[str] = []
        for ref, entry_ops, warnings in manifest.entries():
            diagnostics.extend(
                Diagnostic(
                    Severity.WARNING,
                    "op-ambiguous",
                    f"{path.name}: {ref}: {w}",
                    unit.id,
                    path,
                    subject=f"{unit.id}:{facts.id}",
                )
                for w in warnings
            )
            for full in _resolve_one(ref, unit, path, known_data, diagnostics):
                if full not in resolved:
                    resolved.append(full)
                bucket = ops.setdefault(full, [])
                bucket.extend(o for o in entry_ops if o not in bucket)
        data = tuple(resolved)
    if manifest.exporting is not None:
        diagnostics.append(
            Diagnostic(
                Severity.WARNING,
                "exporting-deprecated",
                f"{path.name}: `exporting` is now `transfers` (GDPR wording)",
                unit.id,
                path,
                subject=f"{unit.id}:{facts.id}",
            )
        )
    transfers = tuple(
        Transfer(
            party=transfer.party,
            data=_resolve_refs(transfer.data, unit, path, known_data, diagnostics),
            purpose=transfer.purpose,
        )
        for transfer in manifest.transfers
    )
    if known_parties is not None:
        diagnostics.extend(
            Diagnostic(
                Severity.ERROR,
                "party-unknown",
                f"{path.name}: transfers to {transfer.party!r}, which is not in "
                "compliance/parties/",
                unit.id,
                path,
            )
            for transfer in transfers
            if transfer.party not in known_parties
        )
    return Touchpoint(
        unit=unit.id,
        facts=facts,
        data=data,
        ops={ref: tuple(o) for ref, o in ops.items()},
        transfers=transfers,
        scope=manifest.scope or infer_scope(facts),
        scope_declared=manifest.scope is not None,
        ignore=manifest.ignore,
        note=manifest.note,
        challenge=manifest.challenge,
        answered=manifest.answered,
        undeclared=tuple(manifest.undeclared),
        stamps=manifest.threats,
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
            manifest = Manifest.model_validate(raw)
            manifest.entries()  # ops vocabulary check, with the ref in the error
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
        except OpError as exc:
            diagnostics.append(
                Diagnostic(
                    Severity.ERROR,
                    "schema-error",
                    f"{path.name}: data: {exc}",
                    unit.id,
                    path,
                )
            )
        else:
            out[path.stem] = manifest
    return out


def write_manifest(
    unit: Unit,
    touchpoint: Touchpoint,
    data: list[str],
    *,
    ops: Mapping[str, Sequence[OpSpec]] | None = None,
    transfers: list[Transfer] | None = None,
    note: str | None = None,
    ignore: bool = False,
    scope: Scope | None = None,
    answered: ManifestChallenge | None = None,
    stamps: Stamps | None = None,
    undeclared: Sequence[Undeclared] | None = None,
) -> Path:
    """Create or replace the manifest of ``touchpoint``; return its path.

    ``undeclared`` (default: the touchpoint's current ones) are carried over
    minus those the new ``transfers`` now declare — declaring the transfer is
    how an undeclared flow is closed.

    ``answered`` records the challenge this declaration closes; ``stamps``
    (default: the touchpoint's current ones) are carried over so a
    re-declaration does not lose the threat review.

    ``ops`` maps a ref (or glob) to its ops; refs absent from it are bare
    reads. Entries are written in the order of ``data``, one per line, the
    ops in the compact manifest form (``ref: create``,
    ``ref: {erase: {by: subject}}``, ``ref: [create, read]``).
    """
    path = unit.folder / TOUCHPOINTS_DIR / f"{touchpoint.slug}.yaml"
    ops = ops or {}
    lines: list[str] = []
    if ignore:
        lines.append("ignore: true")
    if scope is not None:
        lines.append(f"scope: {scope.value}")
    lines.append("data:" if data else "data: []")
    for ref in data:
        lines.extend(_entry_lines(ref, list(ops.get(ref, ()))))
    if transfers:
        lines.append("transfers:")
        for transfer in transfers:
            lines.append(f"  - party: {transfer.party}")
            lines.append("    data: [" + ", ".join(transfer.data) + "]")
            if transfer.purpose:
                lines.append(f"    purpose: {_scalar(transfer.purpose)}")
    if note:
        lines.append(f"note: {_scalar(note)}")
    if answered is not None:
        lines.extend(_challenge_lines("answered", answered))
    kept = touchpoint.undeclared if undeclared is None else tuple(undeclared)
    declared_to = {f"party:{t.party}" for t in transfers or ()}
    lines.extend(_undeclared_lines([u for u in kept if u.sink not in declared_to]))
    if stamps is None:
        # From disk, not from the (possibly cached) touchpoint: a stamp
        # written by another process since must survive the rewrite.
        stamps = read_stamps(path) if path.is_file() else touchpoint.stamps
    lines.extend(stamp_lines(stamps))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _undeclared_lines(found: list[Undeclared]) -> list[str]:
    if not found:
        return []
    lines = ["undeclared:"]
    for entry in found:
        lines.append(f"  - sink: {_scalar(entry.sink)}")
        lines.append("    data: [" + ", ".join(entry.data) + "]")
        lines.append(f"    note: {_scalar(entry.note)}")
        if entry.commit:
            lines.append(f"    commit: {entry.commit}")
        if entry.at:
            lines.append(f"    at: {_scalar(entry.at)}")
    return lines


def _challenge_lines(key: str, challenge: ManifestChallenge) -> list[str]:
    lines = [f"{key}:", f"  commit: {challenge.commit}"]
    if challenge.at:
        lines.append(f"  at: {_scalar(challenge.at)}")
    lines.append(f"  grounds: {_scalar(challenge.grounds)}")
    return lines


def report_undeclared(
    unit: Unit, touchpoint: Touchpoint, found: Undeclared
) -> str | None:
    """Append an ``undeclared:`` entry to an existing manifest; the reason it
    was refused, if so (no manifest, or the sink already declared/reported)."""
    if touchpoint.data is None or touchpoint.ignore:
        return "not declared: declare the touchpoint first (touchpoint_set_data)"
    if any(t.party == found.sink.removeprefix("party:") for t in touchpoint.transfers):
        return f"{found.sink} is already a declared transfer of this touchpoint"
    if any(u.sink == found.sink for u in touchpoint.undeclared):
        return f"{found.sink} is already reported on this touchpoint"
    path = unit.folder / TOUCHPOINTS_DIR / f"{touchpoint.slug}.yaml"
    doc = _yaml().load(path.read_text(encoding="utf-8")) or {}
    entry = {"sink": found.sink, "data": list(found.data), "note": found.note}
    if found.commit:
        entry["commit"] = found.commit
    if found.at:
        entry["at"] = found.at
    doc.setdefault("undeclared", []).append(entry)
    buf = io.StringIO()
    _yaml().dump(doc, buf)
    path.write_text(buf.getvalue(), encoding="utf-8")
    return None


def _yaml() -> RuamelYAML:
    y = RuamelYAML()
    y.preserve_quotes = True
    y.width = 4096
    y.indent(mapping=2, sequence=4, offset=2)
    return y


def challenge_manifest(
    unit: Unit, touchpoint: Touchpoint, *, commit: str, grounds: str
) -> str | None:
    """Add a ``challenge:`` block to an existing manifest; the reason it was
    refused, if so (same rules as :meth:`Lock.challenge`)."""
    if touchpoint.data is None or touchpoint.ignore:
        return "not declared: a pending or ignored touchpoint needs no challenge"
    if touchpoint.challenge is not None:
        return f"already challenged at {touchpoint.challenge.commit}"
    if touchpoint.answered is not None and touchpoint.answered.commit == commit:
        return "already answered by the current declaration"
    path = unit.folder / TOUCHPOINTS_DIR / f"{touchpoint.slug}.yaml"
    text = path.read_text(encoding="utf-8").rstrip("\n")
    at = datetime.now(tz=UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    block = _challenge_lines(
        "challenge", ManifestChallenge(commit=commit, grounds=grounds, at=at)
    )
    path.write_text(text + "\n" + "\n".join(block) + "\n", encoding="utf-8")
    return None


class _FlowDumper(yaml.SafeDumper):
    """Block mappings, flow style for the leaf mappings (``{by: subject}``)."""

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
        """Indent list items under their key."""
        super().increase_indent(flow, False)


def _flow_yaml(value: Any, *, flow: bool | None = None) -> str:
    """Op metadata (a mapping or a list of verbs/mappings) as YAML text.

    ``flow=None`` lets PyYAML pick (block for nested, flow for leaves);
    ``flow=True`` forces the whole value on one line.
    """
    return yaml.dump(
        value,
        Dumper=_FlowDumper,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=flow,
        width=10**6,
    ).rstrip("\n")


def _entry_lines(ref: str, ops: Sequence[OpSpec]) -> list[str]:
    """The manifest lines for one ``data`` entry, as compact as the ops allow."""
    value = render_ops(list(ops))
    if value is None:
        return [f"  - {ref}"]
    if isinstance(value, str):
        return [f"  - {ref}: {value}"]
    if isinstance(value, list) and _shallow(value):
        # ``[read, create, {rectify: {by: staff}}]`` on one line reads better
        # than a block list of three.
        return [f"  - {ref}: {_flow_yaml(value, flow=True)}"]
    return [f"  - {ref}:", *_indent(_flow_yaml(value), 6)]


def _shallow(value: list[Any]) -> bool:
    """Whether every element is a verb or a mapping of plain scalars."""
    return all(
        isinstance(v, str)
        or (
            isinstance(v, dict)
            and all(
                isinstance(m, dict)
                and all(not isinstance(x, dict | list) for x in m.values())
                for m in v.values()
            )
        )
        for v in value
    )


def _indent(text: str, spaces: int) -> list[str]:
    return [" " * spaces + line for line in text.splitlines()]


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
