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
``$types.d.ts`` resolved with the project's TypeScript) and never stored.
What humans (or the agent) write is the optional **declaration**, a row of
the ``touchpoints`` table with its data refs, transfers and store writes.
Read as a mapping (the form :class:`Manifest` validates) it looks like::

    data:                       # data items and what the code does to them
      - api:orders.Order.customer_email: create  # `ref: <op>`, `ref: [ops]`,
      - api:people.User.email: {rectify: {by: subject}}   # or with metadata
      - api:people.User.*: {erase: {by: subject}}         # globs for whole models
      - api:orders.Order.payload@json.iban       # a bare ref = read
    transfers:                  # what leaves to another organisation
      - party: mapbox           # a declared party id
        data: [api:geo.Address.position]
        purpose: geocoding      # optional, one line
    stores:                     # what this code copies into another store
      - store: tmw              # a store slug (or unit:slug)
        data: [api:orders.Order.reference]
        purpose: kitchen board  # optional, one line
    ignore: false               # health checks, static assets

The operations vocabulary lives in :mod:`model_wtf.compliance.ops`. Each
ref carries what this touchpoint *does* to the item (``create``, ``read``,
``rectify``, ``erase``, ``retention_purge``, ...); the rights derivation
reads them, the touchpoint only states facts. ``write`` is a deprecated
alias for ``[create, update]`` and warns.

``transfers`` (GDPR wording, Ch. V / Art. 4(9)) is where the Art. 30
"recipients" column comes from: every call to an external API, every email
provider, every analytics beacon is a transfer of the listed items to that
party. The party must be declared (the agent creates it with ``!todo``
details when it meets a new one); its ``country`` drives the third-country
logic.

``stores`` is the sibling for the project's own second-tier stores: the
data items already say where they *live* (``store: db-default``), a
``stores`` entry says this touchpoint *copies* them somewhere else the
project operates (a realtime document server, a search index, a spreadsheet
export). It is a store flow, not a transfer: no recipient, no Chapter V,
but the store's threat cells apply and the copy shows in the flows.

A touchpoint is **pending** until its declaration has ``data``; the list
names every inventory item the code reads or writes, personal or not (the
register filters on ``pii`` downstream; the data-flow model needs all of
it). An explicit empty list means "touches no inventory item, checked" and
is a valid review. Data references must exist in the inventory of the named
unit; unknown ones are declaration errors.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from fnmatch import fnmatchcase
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select

from model_wtf.compliance.db import get_db
from model_wtf.compliance.declarations import format_errors
from model_wtf.compliance.ops import OpError, OpSpec, Read, parse_ops
from model_wtf.compliance.report import Diagnostic, Severity
from model_wtf.compliance.schemas import StrictModel
from model_wtf.compliance.stamps import Stamps, read_all_stamps
from model_wtf.compliance.tables import (
    StoreWriteRow,
    TouchpointDataRow,
    TouchpointRow,
    TransferRow,
    UndeclaredRow,
)
from model_wtf.introspect.runner import (
    IntrospectionFailed,
    IntrospectionUnavailable,
    is_django_unit,
    run_django_script,
    run_node_script,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from model_wtf.compliance.data import Row
    from model_wtf.compliance.report import Unit

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


class Reach(StrEnum):
    """Who gets past the door — the weakest caller the code lets in.

    Distinct from :class:`Scope` (who the touchpoint is *for*): a webhook
    listing is for the system, yet when its permission list is empty
    anyone on the internet reaches it. The scope drives the rights table,
    the reach drives the likelihood side of a finding's severity.
    """

    ANONYMOUS = "anonymous"
    """No credential checked: anyone."""

    SUBJECT = "subject"
    """Any authenticated account."""

    STAFF = "staff"
    """A staff / admin account."""

    SYSTEM = "system"
    """A shared secret, a signature, a network position: not a person."""


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


def infer_reach(facts: Introspected) -> Reach:
    """Who the code lets in, from the auth facts alone.

    No auth class and no auth wrapper means anyone: the scope does not
    enter into it (a "system" route with an empty permission list is
    public). Tasks are reached by the system only. A custom auth hook
    (``facts.auth_custom``) makes this a guess the reviewer must confirm
    or correct with a declared ``reach``.
    """
    if facts.kind is Kind.TASK:
        return Reach.SYSTEM
    if facts.kind is Kind.ADMIN or _STAFF_ROUTE.match(facts.id):
        return Reach.STAFF
    if not facts.auth:
        return Reach.ANONYMOUS
    auth = " ".join(facts.auth)
    if _STAFF_AUTH.search(auth):
        return Reach.STAFF
    if re.search(r"AllowAny|allow_any", auth) and not re.search(r"guard", auth):
        return Reach.ANONYMOUS
    return Reach.SUBJECT


class Transfer(StrictModel):
    """One outbound flow: these items go to that party (another organisation)."""

    party: str = Field(description="A declared party id")
    data: list[str] = Field(
        default_factory=list, description="Inventory refs of what is sent"
    )
    purpose: str | None = Field(default=None, description="Why, in one line")


Export = Transfer
"""Former name, kept for callers."""


class StoreWrite(StrictModel):
    """One copy into a store of the project: these items are written there."""

    store: str = Field(
        description="Store slug (`tmw`) or `unit:slug` when it is another unit's"
    )
    data: list[str] = Field(
        default_factory=list, description="Inventory refs of what is written"
    )
    purpose: str | None = Field(default=None, description="Why, in one line")


DataEntry = str | dict[str, Any]
"""One ``data`` entry: a bare ref (read) or ``{ref: <ops>}``."""


class Undeclared(StrictModel):
    """A flow a reviewer found in the code that the manifest does not declare:
    data going to a sink (usually a host or a service) nobody accounted for.

    Recorded by ``flow_report``; it is a finding (``flow-undeclared``) and
    makes the touchpoint pending: the declaration is incomplete until the
    transfer (and its party) or the store write are declared, or the code
    stops sending.
    """

    sink: str
    """Where it goes: ``party:<id>`` when the party exists, ``store:<slug>``
    when it is a store of the project, else the host or service name as seen
    in the code (``hooks.zapier.com``)."""
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
    """A touchpoint's declaration, as a mapping."""

    data: list[DataEntry] | None = Field(
        default=None,
        description="Every inventory item touched, as `ref` (a read) or "
        "`{ref: op | [ops]}`; `[]` = checked, touches none; absent = pending",
    )
    transfers: list[Transfer] = Field(
        default_factory=list,
        description="What leaves to another organisation's API",
    )
    stores: list[StoreWrite] = Field(
        default_factory=list,
        description="Copies of the listed items into another store of the "
        "project (a realtime server, a search index): a store flow, not a "
        "transfer",
    )
    scope: Scope | None = Field(
        default=None,
        description="Who this touchpoint serves (subject | staff | public | "
        "system); inferred from auth when absent",
    )
    reach: Reach | None = Field(
        default=None,
        description="The weakest caller the code lets in (anonymous | subject "
        "| staff | system); inferred from auth when absent, required when "
        "the view overrides the auth machinery",
    )
    ignore: bool = Field(
        default=False, description="Plumbing (health check, static asset): skip"
    )
    note: str | None = Field(
        default=None, description="The reviewer's reason, citing file:line"
    )
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
    undeclared: list[Undeclared] = Field(
        default_factory=list,
        description="Flows a reviewer found in the code that this declaration "
        "does not have (see `flow_report`); each is a finding until the "
        "transfer is declared or the code stops sending",
    )

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
    operation_ids: list[str] = Field(default_factory=list)
    """Further ids generated clients call this route by (drf-spectacular
    gives one per method of a DRF route; Ninja's single id is
    ``operation_id``)."""
    auth: list[str] = Field(default_factory=list)
    auth_custom: list[str] = Field(default_factory=list)
    """Where the view overrides the framework's auth machinery
    (``get_permissions (shop.views.Foo)``, a hand-written authentication
    class): ``auth`` is then a claim the reviewer must check."""
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
    own_hosts: list[str] = Field(default_factory=list)
    """Hostnames that are the project itself (ALLOWED_HOSTS, *_URL settings):
    a fetch to one of them is not a transfer."""


@dataclass(frozen=True)
class Touchpoint:
    """One touchpoint with its manifest applied."""

    unit: str
    facts: Introspected
    data: tuple[str, ...] | None = None
    """``unit:id`` data references; ``None`` = no declaration yet (pending)."""
    ops: dict[str, tuple[OpSpec, ...]] = field(default_factory=dict)
    """Per full ref, what this touchpoint does to it (globs expanded)."""
    transfers: tuple[Transfer, ...] = ()
    """Outbound flows to other organisations, refs resolved to full ids."""
    stores: tuple[StoreWrite, ...] = ()
    """Copies into other stores of the project; store as ``unit:slug``."""
    scope: Scope = Scope.PUBLIC
    """Who it serves (see :class:`Scope`); declared or inferred."""
    scope_declared: bool = False
    reach: Reach = Reach.ANONYMOUS
    """The weakest caller the code lets in (see :class:`Reach`); declared
    or inferred from the auth facts."""
    reach_declared: bool = False
    reach_via: str | None = None
    """How an undeclared reach was derived when not from the auth facts:
    ``calls`` (the api touchpoints a front route proxies to gate it) or
    ``layout <route>`` (a parent layout that redirects unauthenticated
    callers). Set by the workspace after linking."""
    ignore: bool = False
    note: str | None = None
    challenge: ManifestChallenge | None = None
    """Open doubt on the declaration; makes the touchpoint pending."""
    answered: ManifestChallenge | None = None
    undeclared: tuple[Undeclared, ...] = ()
    """Flows found in the code and missing from the declaration."""
    stale_undeclared: frozenset[str] = frozenset()
    """Sinks of ``undeclared`` entries the workspace resolved to a declared
    flow or to the project's own host (set by the workspace after linking):
    they do not keep the touchpoint pending and vanish on the next rewrite."""
    stamps: Stamps = field(default_factory=Stamps)
    """Threat stamps recorded on the touchpoint."""
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
    def pending(self) -> bool:
        """Whether it still needs a data declaration (or a re-review after
        a challenge)."""
        if self.ignore:
            return False
        return (
            self.data is None
            or self.challenge is not None
            or self.reach_unverified
            or any(u.sink not in self.stale_undeclared for u in self.undeclared)
        )

    @property
    def reach_unverified(self) -> bool:
        """The view overrides the auth machinery and nobody read it: the
        inferred reach is a guess about a door someone rebuilt."""
        return bool(self.facts.auth_custom) and not self.reach_declared

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
        """The ops on one full ref (``read`` when the declaration is bare)."""
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
            "stores": [e.model_dump() for e in self.stores],
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
    own_hosts: tuple[str, ...] = ()
    """The project's own hostnames, from the introspection."""

    def get(self, touchpoint_id: str) -> Touchpoint | None:
        """Lookup by local id."""
        return next((t for t in self.items if t.id == touchpoint_id), None)

    def visible(self) -> list[Touchpoint]:
        """Items not hidden by ``ignore``."""
        return [t for t in self.items if not t.ignore]


def touchpoint_label(unit_id: str, touchpoint_id: str) -> str:
    """How a declaration is named in diagnostics."""
    return f"touchpoints/{unit_id}:{touchpoint_id}"


def collect_touchpoints(
    unit: Unit,
    *,
    python: str | None = None,
    known_data: dict[str, set[str]] | None = None,
    known_parties: set[str] | None = None,
    known_stores: set[str] | None = None,
) -> UnitTouchpoints:
    """Introspect ``unit`` and apply its declarations.

    ``known_data`` maps unit id → set of data item ids, ``known_parties`` is
    the set of party ids and ``known_stores`` the set of ``unit:slug`` store
    ids, all used to validate what declarations reference. Pass ``None`` to
    skip a validation.
    """
    result = UnitTouchpoints(unit)
    payload = _introspect(unit, result.diagnostics, python=python)
    facts = payload.touchpoints if payload is not None else None
    result.introspected = facts is not None
    result.own_hosts = tuple(payload.own_hosts) if payload is not None else ()
    manifests = _load_manifests(unit, result.diagnostics)
    stamps = read_all_stamps("touchpoint")
    used: set[str] = set()
    for item in facts or []:
        manifest = manifests.get(item.id)
        if manifest is not None:
            used.add(item.id)
        result.items.append(
            _apply(
                unit,
                item,
                manifest,
                known_data,
                result.diagnostics,
                known_parties,
                known_stores,
                stamps=stamps.get((unit.id, item.id), Stamps()),
            )
        )
    for tp_id in sorted(set(manifests) - used):
        result.diagnostics.append(
            Diagnostic(
                Severity.ERROR,
                "touchpoint-orphan-manifest",
                f"{touchpoint_label(unit.id, tp_id)}: no touchpoint {tp_id!r} "
                f"in unit {unit.id}",
                unit.id,
            )
        )
    result.items.sort(key=lambda t: (t.facts.kind.value, t.id))
    return result


def link_calls(all_units: dict[str, UnitTouchpoints]) -> None:
    """Resolve SvelteKit ``calls`` (operation ids) and relative ``fetches``
    to touchpoints of the project.

    Rewrites each front touchpoint's ``calls`` to full ids of the api
    touchpoints whose ``operation_id`` matches (unknown operation ids are
    kept verbatim so they still show up), and adds the touchpoints a raw
    ``fetch("/api/document-sign")`` reaches: a path with no host is the
    project itself — one of its routes when one matches, never a party or
    a store. Such fetches leave ``facts.fetches`` so the flow resolver
    does not see them as an outbound host.
    """
    by_operation: dict[str, str] = {}
    by_path: dict[str, str] = {}
    for unit_tps in all_units.values():
        for tp in unit_tps.items:
            for op_id in (tp.facts.operation_id, *tp.facts.operation_ids):
                if not op_id:
                    continue
                # Generated clients camelise operation ids (``kitchen_orders``
                # -> ``kitchenOrders``); index both spellings.
                by_operation.setdefault(op_id, tp.full_id)
                by_operation.setdefault(_camel(op_id), tp.full_id)
            for route_path in _route_paths(tp):
                by_path.setdefault(route_path, tp.full_id)
    for unit_tps in all_units.values():
        for index, tp in enumerate(unit_tps.items):
            if tp.facts.calls or tp.facts.fetches:
                unit_tps.items[index] = _link_one(tp, by_operation, by_path)


def _link_one(
    tp: Touchpoint, by_operation: dict[str, str], by_path: dict[str, str]
) -> Touchpoint:
    """One touchpoint's ``calls`` resolved and its relative fetches folded
    into them (see :func:`link_calls`)."""
    resolved = [by_operation.get(c, c) for c in tp.facts.calls]
    outbound = []
    for fetched in tp.facts.fetches:
        if not fetched.startswith("/"):
            outbound.append(fetched)
            continue
        target = by_path.get(_norm_path(fetched))
        if target is not None and target not in resolved:
            resolved.append(target)
        # A relative path nothing serves stays internal: dropped from the
        # outbound facts either way.
    facts = tp.facts
    if outbound != list(facts.fetches):
        facts = facts.model_copy(update={"fetches": outbound})
    return replace(tp, facts=facts, calls=tuple(resolved))


def _route_paths(tp: Touchpoint) -> list[str]:
    """Paths a fetch may name this route by: a SvelteKit route ID is the
    path itself (``/api/document-sign``); a Django route's ``path`` is
    relative to the unit's mount (``api/orders/checkout``), so it is
    indexed with and without the ``back/`` prefix the front reaches it by."""
    if tp.facts.kind is not Kind.ROUTE:
        return []
    if tp.facts.path:
        path = _norm_path("/" + tp.facts.path)
        return [path, _norm_path("/back" + path)]
    if tp.id.startswith("/"):
        # A SvelteKit route: the id is the route ID, which is the path.
        return [_norm_path(tp.id)]
    return []


def _norm_path(path: str) -> str:
    """One spelling for a route path and a fetch literal: no query string,
    no trailing slash, SvelteKit layout groups dropped, route params
    (``[id]``, ``<int:pk>``) and template holes (``${id}``) both ``*``."""
    path = path.split("?", 1)[0]
    path = re.sub(r"/\([^)]*\)", "", path)
    path = re.sub(r"\[[^\]]*\]|<[^>]*>|\$\{[^}]*\}", "*", path)
    return re.sub(r"/+", "/", path).rstrip("/") or "/"


def _camel(snake: str) -> str:
    head, *rest = snake.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in rest)


def _introspect(
    unit: Unit, diagnostics: list[Diagnostic], *, python: str | None
) -> Payload | None:
    code_root = unit.code_root
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
    return payload


def _resolve_refs(
    refs: list[str],
    unit: Unit,
    label: str,
    known_data: dict[str, set[str]] | None,
    diagnostics: list[Diagnostic],
) -> list[str]:
    """``unit:id`` for every ref (unit defaults to this one); unknown ones dropped."""
    out: list[str] = []
    for ref in refs:
        out.extend(_resolve_one(ref, unit, label, known_data, diagnostics))
    return out


def _resolve_one(
    ref: str,
    unit: Unit,
    label: str,
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
                f"{label}: {ref!r} names unknown unit {ref_unit!r}",
                unit.id,
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
                    f"{label}: {full!r} matches no data item",
                    unit.id,
                )
            )
        return [f"{ref_unit}:{i}" for i in matched]
    if ref_id not in known_data[ref_unit]:
        diagnostics.append(
            Diagnostic(
                Severity.ERROR,
                "data-ref-unknown",
                f"{label}: no data item {full!r} (`data list` shows the ids)",
                unit.id,
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
    known_stores: set[str] | None = None,
    *,
    stamps: Stamps | None = None,
) -> Touchpoint:
    ignored_by_default = any(p.search(facts.id) for p in IGNORED_BY_DEFAULT)
    if manifest is None:
        return Touchpoint(
            unit=unit.id,
            facts=facts,
            scope=infer_scope(facts),
            reach=infer_reach(facts),
            ignore=ignored_by_default,
            calls=tuple(facts.calls),
            stamps=stamps or Stamps(),
            code_root=unit.code_root,
        )
    label = touchpoint_label(unit.id, facts.id)
    data: tuple[str, ...] | None = None
    ops: dict[str, list[OpSpec]] = {}
    if manifest.data is not None:
        resolved: list[str] = []
        for ref, entry_ops, warnings in manifest.entries():
            diagnostics.extend(
                Diagnostic(
                    Severity.WARNING,
                    "op-ambiguous",
                    f"{label}: {ref}: {w}",
                    unit.id,
                    subject=f"{unit.id}:{facts.id}",
                )
                for w in warnings
            )
            for full in _resolve_one(ref, unit, label, known_data, diagnostics):
                if full not in resolved:
                    resolved.append(full)
                bucket = ops.setdefault(full, [])
                bucket.extend(o for o in entry_ops if o not in bucket)
        data = tuple(resolved)
    transfers = tuple(
        Transfer(
            party=transfer.party,
            data=_resolve_refs(transfer.data, unit, label, known_data, diagnostics),
            purpose=transfer.purpose,
        )
        for transfer in manifest.transfers
    )
    if known_parties is not None:
        diagnostics.extend(
            Diagnostic(
                Severity.ERROR,
                "party-unknown",
                f"{label}: transfers to {transfer.party!r}, which is not a "
                "declared party",
                unit.id,
            )
            for transfer in transfers
            if transfer.party not in known_parties
        )
    stores = tuple(
        StoreWrite(
            store=write.store if ":" in write.store else f"{unit.id}:{write.store}",
            data=_resolve_refs(write.data, unit, label, known_data, diagnostics),
            purpose=write.purpose,
        )
        for write in manifest.stores
    )
    if known_stores is not None:
        diagnostics.extend(
            Diagnostic(
                Severity.ERROR,
                "store-unknown",
                f"{label}: writes to store {write.store!r}, which no unit "
                "declares (store_add / a `stores` row)",
                unit.id,
            )
            for write in stores
            if write.store not in known_stores
        )
    return Touchpoint(
        unit=unit.id,
        facts=facts,
        data=data,
        ops={ref: tuple(o) for ref, o in ops.items()},
        transfers=transfers,
        stores=stores,
        scope=manifest.scope or infer_scope(facts),
        scope_declared=manifest.scope is not None,
        reach=manifest.reach or infer_reach(facts),
        reach_declared=manifest.reach is not None,
        ignore=manifest.ignore,
        note=manifest.note,
        challenge=manifest.challenge,
        answered=manifest.answered,
        undeclared=tuple(manifest.undeclared),
        stamps=stamps or Stamps(),
        calls=tuple(facts.calls),
        code_root=unit.code_root,
    )


def _ops_form(ops: list[Any]) -> Any:
    """The tool form ``[{"op": v, ...}]`` as the manifest form (``v`` or
    ``{v: meta}``); ``None`` for a bare read."""
    forms: list[Any] = []
    for item in ops:
        if not isinstance(item, dict):
            forms.append(item)
            continue
        meta = {k: v for k, v in item.items() if k != "op"}
        verb = item.get("op")
        forms.append({verb: meta} if meta else verb)
    if forms == ["read"]:
        return None
    return forms[0] if len(forms) == 1 else forms


def _manifest_raw(row: TouchpointRow) -> dict[str, Any]:
    """A ``touchpoints`` row (and its children) as the mapping
    :class:`Manifest` validates."""
    raw: dict[str, Any] = {"ignore": row.ignore}
    if row.declared:
        entries: list[Any] = []
        for item in row.data:
            value = _ops_form(list(item.ops or []))
            entries.append(item.ref if value is None else {item.ref: value})
        raw["data"] = entries
    if row.transfers:
        raw["transfers"] = [
            {"party": t.party_id, "data": list(t.data), "purpose": t.purpose}
            for t in row.transfers
        ]
    if row.store_writes:
        raw["stores"] = [
            {"store": w.store, "data": list(w.data), "purpose": w.purpose}
            for w in row.store_writes
        ]
    if row.undeclared:
        raw["undeclared"] = [
            {
                "sink": u.sink,
                "data": list(u.data),
                "note": u.note,
                "commit": u.commit,
                "at": u.at,
            }
            for u in row.undeclared
        ]
    for key in ("scope", "reach", "note", "challenge", "answered"):
        value = getattr(row, key)
        if value is not None:
            raw[key] = value
    return raw


def declared_touchpoints(unit_id: str) -> dict[str, dict[str, Any]]:
    """Raw declarations of a unit, by touchpoint id."""
    with get_db() as db:
        rows = db.scalars(
            select(TouchpointRow)
            .where(TouchpointRow.unit == unit_id)
            .order_by(TouchpointRow.id)
        ).all()
        return {row.id: _manifest_raw(row) for row in rows}


def _load_manifests(unit: Unit, diagnostics: list[Diagnostic]) -> dict[str, Manifest]:
    out: dict[str, Manifest] = {}
    for tp_id, raw in declared_touchpoints(unit.id).items():
        label = touchpoint_label(unit.id, tp_id)
        try:
            manifest = Manifest.model_validate(raw)
            manifest.entries()  # ops vocabulary check, with the ref in the error
        except ValidationError as exc:
            diagnostics.extend(
                Diagnostic(
                    Severity.ERROR,
                    "schema-error",
                    f"{label}: {loc}: {msg}",
                    unit.id,
                )
                for loc, msg in format_errors(exc)
            )
        except OpError as exc:
            diagnostics.append(
                Diagnostic(
                    Severity.ERROR,
                    "schema-error",
                    f"{label}: data: {exc}",
                    unit.id,
                )
            )
        else:
            out[tp_id] = manifest
    return out


def _ops_json(ops: Sequence[OpSpec]) -> list[dict[str, Any]]:
    """Ops in the tool form stored in the database."""
    return [{"op": op.op.value, **op.payload()} for op in ops] or [{"op": "read"}]


def write_manifest(
    unit: Unit,
    touchpoint: Touchpoint,
    data: list[str],
    *,
    ops: Mapping[str, Sequence[OpSpec]] | None = None,
    transfers: list[Transfer] | None = None,
    stores: list[StoreWrite] | None = None,
    note: str | None = None,
    ignore: bool = False,
    scope: Scope | None = None,
    reach: Reach | None = None,
    answered: ManifestChallenge | None = None,
    undeclared: Sequence[Undeclared] | None = None,
    resolve_sink: Callable[[str], str] | None = None,
) -> None:
    """Create or replace the declaration of ``touchpoint``.

    ``undeclared`` (default: the touchpoint's current ones) are carried over
    minus those the new ``transfers`` / ``stores`` now declare — declaring
    the flow is how an undeclared one is closed. ``resolve_sink`` maps a
    reviewer's free-text sink to its canonical ``party:``/``store:`` id so
    entries recorded before the party or store existed close too.

    ``answered`` records the challenge this declaration closes; the
    threat stamps live in their own table and survive a re-declaration.

    ``ops`` maps a ref (or glob) to its ops; refs absent from it are bare
    reads. Entries are kept in the order of ``data``.
    """
    ops = ops or {}
    kept = touchpoint.undeclared if undeclared is None else tuple(undeclared)
    declared_to = {f"party:{t.party}" for t in transfers or ()}
    for write in stores or ():
        declared_to.add(f"store:{write.store}")
        if ":" not in write.store:
            declared_to.add(f"store:{unit.id}:{write.store}")
    resolve = resolve_sink or (lambda sink: sink)
    still = [
        u
        for u in kept
        if resolve(u.sink) not in declared_to and not resolve(u.sink).startswith("own:")
    ]
    with get_db() as db:
        row = db.get(TouchpointRow, (unit.id, touchpoint.id))
        if row is None:
            row = TouchpointRow(unit=unit.id, id=touchpoint.id)
            db.add(row)
        row.declared = True
        row.ignore = ignore
        row.scope = scope.value if scope is not None else None
        row.reach = reach.value if reach is not None else None
        row.note = note or None
        row.challenge = None
        row.answered = (
            answered.model_dump(mode="json", exclude_none=True) if answered else None
        )
        row.data = [
            TouchpointDataRow(
                unit=unit.id,
                touchpoint_id=touchpoint.id,
                ref=ref,
                position=index,
                ops=_ops_json(list(ops.get(ref, ()))),
            )
            for index, ref in enumerate(data)
        ]
        row.transfers = [
            TransferRow(
                unit=unit.id,
                touchpoint_id=touchpoint.id,
                party_id=t.party,
                position=index,
                data=list(t.data),
                purpose=t.purpose,
            )
            for index, t in enumerate(transfers or [])
        ]
        row.store_writes = [
            StoreWriteRow(
                unit=unit.id,
                touchpoint_id=touchpoint.id,
                store=w.store,
                position=index,
                data=list(w.data),
                purpose=w.purpose,
            )
            for index, w in enumerate(stores or [])
        ]
        row.undeclared = [
            UndeclaredRow(
                unit=unit.id,
                touchpoint_id=touchpoint.id,
                sink=u.sink,
                position=index,
                data=list(u.data),
                note=u.note,
                commit=u.commit,
                at=u.at,
            )
            for index, u in enumerate(still)
        ]


def report_undeclared(
    unit: Unit, touchpoint: Touchpoint, found: Undeclared
) -> str | None:
    """Add an undeclared flow to an existing declaration; the reason it was
    refused, if so (no declaration, or the sink already declared/reported)."""
    if touchpoint.data is None or touchpoint.ignore:
        return "not declared: declare the touchpoint first (touchpoint_set_data)"
    if any(t.party == found.sink.removeprefix("party:") for t in touchpoint.transfers):
        return f"{found.sink} is already a declared transfer of this touchpoint"
    if any(f"store:{w.store}" == found.sink for w in touchpoint.stores):
        return f"{found.sink} is already a declared store write of this touchpoint"
    if any(u.sink == found.sink for u in touchpoint.undeclared):
        return f"{found.sink} is already reported on this touchpoint"
    with get_db() as db:
        row = db.get(TouchpointRow, (unit.id, touchpoint.id))
        if row is None:
            return "not declared: declare the touchpoint first (touchpoint_set_data)"
        row.undeclared.append(
            UndeclaredRow(
                unit=unit.id,
                touchpoint_id=touchpoint.id,
                sink=found.sink,
                position=len(row.undeclared),
                data=list(found.data),
                note=found.note,
                commit=found.commit,
                at=found.at,
            )
        )
    return None


def challenge_manifest(
    unit: Unit, touchpoint: Touchpoint, *, commit: str, grounds: str
) -> str | None:
    """Record a challenge on an existing declaration; the reason it was
    refused, if so (same rules as :meth:`Lock.challenge`)."""
    if touchpoint.data is None or touchpoint.ignore:
        return "not declared: a pending or ignored touchpoint needs no challenge"
    if touchpoint.challenge is not None:
        return f"already challenged at {touchpoint.challenge.commit}"
    if touchpoint.answered is not None and touchpoint.answered.commit == commit:
        return "already answered by the current declaration"
    at = datetime.now(tz=UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    with get_db() as db:
        row = db.get(TouchpointRow, (unit.id, touchpoint.id))
        if row is None:
            return "not declared: a pending or ignored touchpoint needs no challenge"
        row.challenge = ManifestChallenge(
            commit=commit, grounds=grounds, at=at
        ).model_dump(mode="json", exclude_none=True)
    return None


def touchpoints_using(data_ref: str) -> list[tuple[str, str]]:
    """``(unit, touchpoint id)`` of every declaration listing ``data_ref``
    verbatim (globs are expanded by the workspace, not here)."""
    with get_db() as db:
        rows = db.execute(
            select(TouchpointDataRow.unit, TouchpointDataRow.touchpoint_id).where(
                TouchpointDataRow.ref == data_ref
            )
        ).all()
    return [(unit, tp_id) for unit, tp_id in rows]


def data_index(rows_by_unit: dict[str, list[Row]]) -> dict[str, set[str]]:
    """``{unit: {item ids}}`` from collected data rows, for reference checks."""
    return {unit: {r.id for r in rows} for unit, rows in rows_by_unit.items()}
