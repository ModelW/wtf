"""Stores: where data physically lives, one slug per store.

A store is a database, a cache, a bucket, a queue, a search index... The
registry asks *where* data is kept, transfers and retention are decided per
store, so stores are items with a stable **slug** that data rows reference
(``store: db-default``) instead of carrying a free-form label.

The inventory is introspected from the Django settings by the in-venv
script (``DATABASES`` → ``db-<alias>``, ``CACHES`` → ``cache-<alias>``,
``STORAGES`` → ``files-<alias>``, brokers → ``queue-*``, search backends →
``search-<alias>``); nothing has to be written for the common case. A store
is described by its slug, its ``type`` and a conceptual ``backend``
(``postgresql``, ``redis``, ``s3``): hosts, bucket names and credentials are
deployment facts and never appear here. The optional ``stores`` row of a
unit can still:

* **override** facts of an introspected store (a human ``name``, the
  ``provider``, ``location`` as a region/country, ``retention``...);
* **declare** a store the settings do not show (an external SaaS, a
  spreadsheet, the browser's localStorage in a front unit) so manual data
  items can reference it — such a row must give ``type``;
* **hide** a store with ``ignore`` (a test database); hidden stores must
  not be referenced by any row.

One store is one row: :func:`save_store` refuses a manual store that looks
like a store the unit already has — a shared host or settings name, a
name or a slug that normalises to an existing one's (see
:mod:`model_wtf.compliance.parties` for the name rules) — unless
``distinct_from`` names it, and :func:`collect_stores` reports lookalikes
that already coexist as a ``store-duplicate`` error.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import Field, ValidationError
from sqlalchemy import select

from model_wtf.compliance.db import get_db
from model_wtf.compliance.declarations import format_errors
from model_wtf.compliance.parties import names_alike, normalise_name
from model_wtf.compliance.report import Diagnostic, Severity, marker_diagnostics
from model_wtf.compliance.schemas import NonEmpty, StrictModel
from model_wtf.compliance.stamps import Stamps, read_all_stamps
from model_wtf.compliance.tables import (
    DataItemRow,
    StampRow,
    StoreHostRow,
    StoreRow,
    StoreWriteRow,
)
from model_wtf.compliance.yaml_io import Marker

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from model_wtf.compliance.report import Unit
    from model_wtf.introspect.runner import Inventory


class StoreType(StrEnum):
    """Fixed vocabulary; the registry needs to group by it."""

    DATABASE = "database"
    CACHE = "cache"
    BUCKET = "bucket"
    FILESYSTEM = "filesystem"
    QUEUE = "queue"
    SEARCH = "search"
    REALTIME = "realtime"
    """A live document / collaboration server (Hocuspocus, Firebase RTDB)."""
    MAIL = "mail"
    """Outgoing email: the application mails, how the mail is sent is
    infrastructure."""
    MONITORING = "monitoring"
    """Error / performance monitoring (Sentry): events the application
    emits about itself; where they land is infrastructure."""
    EXTERNAL = "external"
    BROWSER = "browser"


class StoreSource(StrEnum):
    """Where a store's facts come from."""

    CONFIG = "config"
    OVERRIDE = "override"
    MANUAL = "manual"


class StoreSpec(StrictModel):
    """A ``stores`` row: overrides for a known slug, or a manual store.

    Every field is optional so an override can touch one fact; a manual
    store (slug unknown to the config) must at least carry ``type``.
    """

    type: StoreType | None = Field(
        default=None, description="Mandatory for a store the settings do not show"
    )
    backend: NonEmpty | None = Field(
        default=None,
        description="Conceptual backend: postgresql, redis, s3, hocuspocus",
    )
    name: NonEmpty | Marker | None = Field(
        default=None, description="Human name of the store"
    )
    provider: NonEmpty | Marker | None = Field(
        default=None, description="Who operates it (party id or vendor name)"
    )
    location: NonEmpty | Marker | None = Field(
        default=None, description="Region the data sits in (country / region id)"
    )
    retention: NonEmpty | Marker | None = Field(
        default=None, description="How long records stay in this store"
    )
    description: NonEmpty | Marker | None = Field(
        default=None, description="What this store holds, in one sentence"
    )
    hosts: list[NonEmpty] = Field(
        default_factory=list,
        description=(
            "Hostnames the code reaches this store at, or the names of the "
            "settings holding its URL (`TMW_URL`); a fetch to one of them is "
            "a write to this store, not a transfer"
        ),
    )
    ignore: bool = Field(default=False, description="Hide the store (a test database)")
    distinct_from: list[NonEmpty] = Field(
        default_factory=list,
        description="Slugs of stores of this unit that this one resembles (a shared "
        "host, a similar name or slug) but is not: silences the duplicate guard",
    )


StoreFile = StoreSpec
"""Former name, kept for callers."""


@dataclass(frozen=True)
class Store:
    """One store, introspected and/or declared."""

    unit: str
    slug: str
    type: StoreType
    source: StoreSource
    backend: str = ""
    """Conceptual backend (``postgresql``, ``redis``, ``s3``); empty if unknown."""
    config: str = ""
    """Settings key it came from (``DATABASES['default']``); empty if manual."""
    name: str | None = None
    provider: str | None = None
    location: str | None = None
    retention: str | None = None
    description: str | None = None
    ignore: bool = False
    hosts: tuple[str, ...] = ()
    """Hostnames / URL setting names that reach this store (declared)."""
    distinct_from: tuple[str, ...] = ()
    """Slugs this store was declared distinct from (duplicate guard)."""
    stamps: Stamps = field(default_factory=Stamps)
    """Threat stamps recorded on the store."""

    @property
    def fingerprint(self) -> str:
        """What a threat stamp on the store looked at: type, backend, config."""
        text = f"{self.type.value}|{self.backend}|{self.config or ''}"
        return hashlib.sha256(text.encode()).hexdigest()[:8]

    @property
    def full_slug(self) -> str:
        """``unit:slug``."""
        return f"{self.unit}:{self.slug}"

    def to_dict(self) -> dict[str, Any]:
        """JSON form."""
        return {
            "unit": self.unit,
            "slug": self.slug,
            "type": self.type.value,
            "source": self.source.value,
            "backend": self.backend,
            "config": self.config,
            "name": self.name,
            "provider": self.provider,
            "location": self.location,
            "retention": self.retention,
            "description": self.description,
            "ignore": self.ignore,
            "hosts": list(self.hosts),
            "distinct_from": list(self.distinct_from),
        }


@dataclass
class UnitStores:
    """Stores of one unit plus the diagnostics raised while loading them."""

    stores: dict[str, Store] = field(default_factory=dict)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    sessions_store: str | None = None

    def get(self, slug: str | None) -> Store | None:
        """Lookup tolerant of ``None`` (manual data items without a store)."""
        return self.stores.get(slug) if slug else None

    def visible(self) -> list[Store]:
        """Stores not hidden by ``ignore``, in slug order."""
        return [s for s in self.stores.values() if not s.ignore]


def store_label(unit_id: str, slug: str) -> str:
    """How a store row is named in diagnostics."""
    return f"stores/{unit_id}:{slug}"


def _row_raw(row: StoreRow) -> dict[str, Any]:
    raw: dict[str, Any] = {"hosts": [h.host for h in row.hosts], "ignore": row.ignore}
    if row.distinct_from:
        raw["distinct_from"] = list(row.distinct_from)
    for key in (
        "type",
        "backend",
        "name",
        "provider",
        "location",
        "retention",
        "description",
    ):
        value = getattr(row, key)
        if value is not None:
            raw[key] = value
    return raw


def declared_stores(unit_id: str) -> dict[str, dict[str, Any]]:
    """Raw ``stores`` rows of a unit, by slug."""
    with get_db() as db:
        rows = db.scalars(
            select(StoreRow).where(StoreRow.unit == unit_id).order_by(StoreRow.slug)
        ).all()
        return {row.slug: _row_raw(row) for row in rows}


def collect_stores(unit: Unit, inventory: Inventory | None) -> UnitStores:
    """Merge the introspected stores with the unit's declared ``stores`` rows."""
    result = UnitStores()
    stamps = read_all_stamps("store")
    if inventory is not None:
        result.sessions_store = inventory.sessions.store if inventory.sessions else None
        for info in inventory.stores:
            try:
                kind = StoreType(info.type)
            except ValueError:
                kind = StoreType.EXTERNAL
            result.stores[info.slug] = Store(
                unit=unit.id,
                slug=info.slug,
                type=kind,
                source=StoreSource.CONFIG,
                backend=info.backend,
                config=info.config,
                hosts=tuple(info.hosts),
                stamps=stamps.get((unit.id, info.slug), Stamps()),
            )
    for slug, raw in declared_stores(unit.id).items():
        declared = _validate(raw, unit, slug, result.diagnostics)
        if declared is None:
            continue
        base = result.stores.get(slug)
        if base is None and declared.type is None:
            result.diagnostics.append(
                Diagnostic(
                    Severity.ERROR,
                    "store-orphan",
                    f"{store_label(unit.id, slug)}: no store {slug!r} in the "
                    "settings; a manual store needs at least `type`",
                    unit.id,
                )
            )
            continue
        result.stores[slug] = _merge(
            unit, slug, base, declared, stamps.get((unit.id, slug), Stamps())
        )
    result.diagnostics.extend(_duplicates(unit, result))
    return result


def _duplicates(unit: Unit, stores: UnitStores) -> list[Diagnostic]:
    """One ``store-duplicate`` error per pair of visible stores of the unit
    that look like the same store, unless one names the other in
    ``distinct_from``."""
    visible = stores.visible()
    out = []
    for i, a in enumerate(visible):
        for b in visible[i + 1 :]:
            reason = lookalike_reason(a, b)
            if reason is None or b.slug in a.distinct_from or a.slug in b.distinct_from:
                continue
            out.append(
                Diagnostic(
                    Severity.ERROR,
                    "store-duplicate",
                    f"stores {unit.id}:{a.slug} and {unit.id}:{b.slug} look like "
                    f"the same store (same {reason}); merge them, or set "
                    "distinct_from on one if they are not",
                    unit.id,
                    subject=f"stores/{unit.id}:{a.slug}+{b.slug}",
                )
            )
    return out


def _host_keys(hosts: tuple[str, ...] | list[str]) -> set[str]:
    """Hosts lower-cased; a settings name keeps its case-insensitive form."""
    return {h.strip().lower() for h in hosts if h.strip()}


def lookalike_reason(a: Store, b: Store) -> str | None:
    """Why ``a`` and ``b`` may be one store: a shared host / settings name,
    alike names (a human name, or the slug when there is none), alike
    slugs; ``None`` when they look different.

    Introspected stores of different slugs are what the settings say, two
    of them are never lookalikes of each other; the check is about manual
    rows duplicating a config store or one another.
    """
    if a.source is StoreSource.CONFIG and b.source is StoreSource.CONFIG:
        return None
    shared = _host_keys(a.hosts) & _host_keys(b.hosts)
    if shared:
        return f"host {sorted(shared)[0]}"
    # A config store has no human name: its slug and its backend are what
    # people call it, so "Mail default" duplicates `mail-default` and
    # "Sentry SDK ingest" duplicates `errors-sentry` (backend `sentry`).
    if any(names_alike(x, y) for x in _name_labels(a) for y in _name_labels(b)):
        return "name"
    if names_alike(normalise_name(a.slug), normalise_name(b.slug)):
        return "slug"
    return None


def _name_labels(store: Store) -> set[str]:
    labels = {normalise_name(store.name or store.slug)}
    if store.source is StoreSource.CONFIG and store.backend:
        labels.add(normalise_name(store.backend))
    return labels - {""}


def find_store_lookalikes(
    unit: Unit, stores: UnitStores, slug: str, spec: dict[str, Any]
) -> list[tuple[Store, str]]:
    """Visible stores of ``unit`` a new manual store ``(slug, spec)`` may
    duplicate, with the reason, minus those ``spec`` is ``distinct_from``."""
    hosts = [str(h) for h in spec.get("hosts") or []]
    name = spec.get("name")
    candidate = Store(
        unit=unit.id,
        slug=slug,
        type=StoreType.EXTERNAL,
        source=StoreSource.MANUAL,
        name=name if isinstance(name, str) else None,
        hosts=tuple(hosts),
    )
    distinct = {str(s) for s in spec.get("distinct_from") or []}
    out = []
    for other in stores.visible():
        if other.slug == slug or other.slug in distinct:
            continue
        reason = lookalike_reason(candidate, other)
        if reason is not None:
            out.append((other, reason))
    return out


class DuplicateStore(ValueError):
    """A manual store that looks like one the unit already has was refused."""

    def __init__(
        self, unit_id: str, slug: str, lookalikes: list[tuple[Store, str]]
    ) -> None:
        self.lookalikes = lookalikes
        listed = "; ".join(
            f"{s.slug} ({s.name or s.backend or s.type.value}; same {why})"
            for s, why in lookalikes
        )
        slugs = ", ".join(repr(s.slug) for s, _ in lookalikes)
        super().__init__(
            f"store {unit_id}:{slug} looks like an existing store: {listed}. Use "
            f"that slug if it is the same store; if it is not, declare it again "
            f"with distinct_from=[{slugs}]"
        )


def _merge(
    unit: Unit, slug: str, base: Store | None, declared: StoreSpec, stamps: Stamps
) -> Store:
    def text(value: str | Marker | None) -> str | None:
        return None if value is None or isinstance(value, Marker) else value

    if base is None:
        assert declared.type is not None  # noqa: S101 - checked by caller
        return Store(
            unit=unit.id,
            slug=slug,
            type=declared.type,
            source=StoreSource.MANUAL,
            backend=declared.backend or "",
            name=text(declared.name),
            provider=text(declared.provider),
            location=text(declared.location),
            retention=text(declared.retention),
            description=text(declared.description),
            ignore=declared.ignore,
            hosts=tuple(declared.hosts),
            distinct_from=tuple(declared.distinct_from),
            stamps=stamps,
        )
    return Store(
        unit=unit.id,
        slug=slug,
        type=declared.type or base.type,
        source=StoreSource.OVERRIDE,
        backend=declared.backend or base.backend,
        config=base.config,
        name=text(declared.name) or base.name,
        provider=text(declared.provider) or base.provider,
        location=text(declared.location) or base.location,
        retention=text(declared.retention) or base.retention,
        description=text(declared.description) or base.description,
        ignore=declared.ignore,
        hosts=tuple(declared.hosts) or base.hosts,
        distinct_from=tuple(declared.distinct_from),
        stamps=stamps,
    )


def _validate(
    raw: dict[str, Any], unit: Unit, slug: str, diagnostics: list[Diagnostic]
) -> StoreSpec | None:
    label = store_label(unit.id, slug)
    try:
        declared = StoreSpec.model_validate(raw)
    except ValidationError as exc:
        diagnostics.extend(
            Diagnostic(
                Severity.ERROR, "schema-error", f"{label}: {loc}: {msg}", unit.id
            )
            for loc, msg in format_errors(exc)
        )
        return None
    diagnostics.extend(marker_diagnostics(declared, label, unit.id))
    return declared


def save_store(unit_id: str, slug: str, spec: dict[str, Any]) -> bool:
    """Create a ``stores`` row from a raw :class:`StoreSpec` mapping;
    ``False`` when the slug already has one. Unknown keys and bad types are
    stored as given and reported by ``check`` (a bad declaration is a
    declaration error, not a refused write)."""
    with get_db() as db:
        if db.get(StoreRow, (unit_id, slug)) is not None:
            return False
        hosts = [str(h) for h in spec.get("hosts") or []]
        row = StoreRow(
            unit=unit_id,
            slug=slug,
            type=spec.get("type"),
            backend=spec.get("backend"),
            name=spec.get("name"),
            provider=spec.get("provider"),
            location=spec.get("location"),
            retention=spec.get("retention"),
            description=spec.get("description"),
            ignore=bool(spec.get("ignore", False)),
            distinct_from=[str(s) for s in spec.get("distinct_from") or []] or None,
        )
        row.hosts = [StoreHostRow(unit=unit_id, slug=slug, host=h) for h in hosts]
        db.add(row)
    return True


STORE_FACTS = frozenset(
    {"name", "backend", "provider", "location", "retention", "description"}
)
"""Scalar columns ``update_store`` may set or clear."""


def update_store(unit_id: str, slug: str, **changes: Any) -> None:
    """Set columns of a store row, creating the row for a config store
    (the settings show it, a human adds facts). ``hosts`` replaces the
    list; ``ignore`` is a bool; ``None`` clears a fact."""
    unknown = set(changes) - STORE_FACTS - {"hosts", "ignore"}
    if unknown:
        msg = f"unknown store fields: {', '.join(sorted(unknown))}"
        raise ValueError(msg)
    with get_db() as db:
        row = _row_for(db, unit_id, slug)
        for key, value in changes.items():
            if key == "hosts":
                row.hosts = [
                    StoreHostRow(unit=unit_id, slug=slug, host=h) for h in value
                ]
            elif key == "ignore":
                row.ignore = bool(value)
            else:
                setattr(row, key, value)


def store_usage(unit_id: str, slug: str) -> dict[str, list[str]]:
    """What refers to a store row: ``writes`` (``unit:touchpoint``),
    ``items`` (data items placed in it), ``distinct_in`` (stores naming it)."""
    with get_db() as db:
        writes = [
            f"{w.unit}:{w.touchpoint_id}"
            for w in db.scalars(
                select(StoreWriteRow)
                .where(_writes_to(unit_id, slug))
                .order_by(StoreWriteRow.unit, StoreWriteRow.touchpoint_id)
            )
        ]
        items = [
            row.id
            for row in db.scalars(
                select(DataItemRow)
                .where(DataItemRow.unit == unit_id, DataItemRow.store == slug)
                .order_by(DataItemRow.id)
            )
        ]
        distinct_in = [
            row.slug
            for row in db.scalars(
                select(StoreRow).where(StoreRow.unit == unit_id).order_by(StoreRow.slug)
            )
            if slug in (row.distinct_from or [])
        ]
    return {"writes": writes, "items": items, "distinct_in": distinct_in}


def merge_store(unit_id: str, loser: str, winner: str) -> dict[str, list[str]]:
    """Fold the manual (or override) row ``loser`` into ``winner``: writes
    and data-item placements move, the loser's hosts and filled-in facts
    complete the winner's, stamps move, the loser's row goes. ``winner``
    needs no row (a config store). Returns what moved.

    Raises ``KeyError`` when ``loser`` has no row, ``ValueError`` when both
    are one.
    """
    if loser == winner:
        msg = "a store cannot be merged into itself"
        raise ValueError(msg)
    usage = store_usage(unit_id, loser)
    with get_db() as db:
        lose = db.get(StoreRow, (unit_id, loser))
        if lose is None:
            raise KeyError(loser)
        win = db.get(StoreRow, (unit_id, winner))
        if win is not None:
            _complete_store_facts(win, lose)
        _move_store_writes(db, unit_id, loser, winner)
        for item in db.scalars(
            select(DataItemRow).where(
                DataItemRow.unit == unit_id, DataItemRow.store == loser
            )
        ):
            item.store = winner
        _move_store_distinctions(db, unit_id, loser, winner)
        _move_store_stamps(db, unit_id, loser, winner)
        db.delete(lose)
    return usage


def _complete_store_facts(win: StoreRow, lose: StoreRow) -> None:
    for key in ("name", "provider", "location", "retention", "description"):
        current, other = getattr(win, key), getattr(lose, key)
        if (current is None or isinstance(current, Marker)) and (
            other is not None and not isinstance(other, Marker)
        ):
            setattr(win, key, other)
    known = {h.host for h in win.hosts}
    win.hosts.extend(
        StoreHostRow(unit=win.unit, slug=win.slug, host=h.host)
        for h in lose.hosts
        if h.host not in known
    )
    win.distinct_from = [
        x for x in (win.distinct_from or []) if x not in (lose.slug, win.slug)
    ] or None


def _writes_to(unit_id: str, slug: str) -> Any:
    """Filter for the writes to a store: the column holds ``slug`` (written
    from inside the unit) or ``unit:slug``."""
    return StoreWriteRow.store.in_([slug, f"{unit_id}:{slug}"])


def _move_store_writes(db: Session, unit_id: str, loser: str, winner: str) -> None:
    win_full = f"{unit_id}:{winner}"
    for w in db.scalars(select(StoreWriteRow).where(_writes_to(unit_id, loser))):
        existing = db.get(StoreWriteRow, (w.unit, w.touchpoint_id, win_full))
        if existing is None and w.unit == unit_id:
            existing = db.get(StoreWriteRow, (w.unit, w.touchpoint_id, winner))
        if existing is None:
            w.store = win_full
            continue
        merged = list(existing.data)
        merged.extend(d for d in w.data if d not in merged)
        existing.data = merged
        existing.purpose = existing.purpose or w.purpose
        db.delete(w)


def _move_store_distinctions(
    db: Session, unit_id: str, loser: str, winner: str
) -> None:
    for row in db.scalars(select(StoreRow).where(StoreRow.unit == unit_id)):
        listed = list(row.distinct_from or [])
        if row.slug == winner or loser not in listed:
            continue
        listed = [x for x in listed if x not in (loser, row.slug)]
        if winner not in listed:
            listed.append(winner)
        row.distinct_from = listed or None


def _move_store_stamps(db: Session, unit_id: str, loser: str, winner: str) -> None:
    for st in db.scalars(
        select(StampRow).where(
            StampRow.holder_kind == "store",
            StampRow.holder_unit == unit_id,
            StampRow.holder_id == loser,
        )
    ):
        if db.get(StampRow, ("store", unit_id, winner, st.key)) is None:
            st.holder_id = winner
        else:
            db.delete(st)


def remove_store(
    unit_id: str, slug: str, *, force: bool = False
) -> dict[str, list[str]]:
    """Delete a store row nothing refers to; the usage when something does
    (and the row stays). With ``force`` the writes to it go too and the
    data items placed in it fall back to what the code says.

    Raises ``KeyError`` when no such row.
    """
    usage = store_usage(unit_id, slug)
    if any(usage.values()) and not force:
        return usage
    with get_db() as db:
        row = db.get(StoreRow, (unit_id, slug))
        if row is None:
            raise KeyError(slug)
        for w in db.scalars(select(StoreWriteRow).where(_writes_to(unit_id, slug))):
            db.delete(w)
        for item in db.scalars(
            select(DataItemRow).where(
                DataItemRow.unit == unit_id, DataItemRow.store == slug
            )
        ):
            item.store = None
        for other in db.scalars(select(StoreRow).where(StoreRow.unit == unit_id)):
            if slug in (other.distinct_from or []):
                other.distinct_from = [
                    x for x in other.distinct_from or [] if x != slug
                ] or None
        for st in db.scalars(
            select(StampRow).where(
                StampRow.holder_kind == "store",
                StampRow.holder_unit == unit_id,
                StampRow.holder_id == slug,
            )
        ):
            db.delete(st)
        db.delete(row)
    return usage


def set_store_distinct(unit_id: str, slug: str, others: list[str]) -> list[str]:
    """Record that ``slug`` is a different store from each of ``others``
    (a row is created for a config store that has none, so the decision
    has somewhere to live). Returns the store's full ``distinct_from``."""
    with get_db() as db:
        row = _row_for(db, unit_id, slug)
        for other in others:
            if other == slug:
                continue
            other_row = _row_for(db, unit_id, other)
            mine = list(row.distinct_from or [])
            if other not in mine:
                mine.append(other)
            row.distinct_from = mine
            theirs = list(other_row.distinct_from or [])
            if slug not in theirs:
                theirs.append(slug)
            other_row.distinct_from = theirs
        return list(row.distinct_from or [])


def _row_for(db: Session, unit_id: str, slug: str) -> StoreRow:
    row = db.get(StoreRow, (unit_id, slug))
    if row is None:
        row = StoreRow(unit=unit_id, slug=slug)
        db.add(row)
    return row


__all__ = [
    "STORE_FACTS",
    "DuplicateStore",
    "Store",
    "StoreFile",
    "StoreSource",
    "StoreSpec",
    "StoreType",
    "UnitStores",
    "collect_stores",
    "declared_stores",
    "find_store_lookalikes",
    "lookalike_reason",
    "merge_store",
    "remove_store",
    "save_store",
    "set_store_distinct",
    "store_label",
    "store_usage",
]
