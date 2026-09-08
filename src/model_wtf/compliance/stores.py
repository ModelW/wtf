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
deployment facts and never appear here. The optional
``<unit>/compliance/stores/<slug>.yaml`` layer can still:

* **override** facts of an introspected store (a human ``name``, the
  ``provider``, ``location`` as a region/country, ``retention``...);
* **declare** a store the settings do not show (an external SaaS, a
  spreadsheet, the browser's localStorage in a front unit) so manual data
  items can reference it — such a file must give ``type``;
* **hide** a store with ``ignore: true`` (a test database); hidden stores
  must not be referenced by any row.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import Field, ValidationError

from model_wtf.compliance.declarations import format_errors
from model_wtf.compliance.report import Diagnostic, Severity, marker_diagnostics
from model_wtf.compliance.schemas import NonEmpty, StrictModel
from model_wtf.compliance.stamps import Stamps
from model_wtf.compliance.yaml_io import Marker, load_yaml

if TYPE_CHECKING:
    from pathlib import Path

    from model_wtf.compliance.report import Unit
    from model_wtf.introspect.runner import Inventory

STORES_DIR = "stores"


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
    EXTERNAL = "external"
    BROWSER = "browser"


class StoreSource(StrEnum):
    """Where a store's facts come from."""

    CONFIG = "config"
    OVERRIDE = "override"
    MANUAL = "manual"


class StoreFile(StrictModel):
    """``stores/<slug>.yaml``: overrides for a known slug, or a manual store.

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
    threats: Stamps = Field(
        default_factory=Stamps,
        description="Stamps closing the threat cells the matrix left open",
    )
    ignore: bool = Field(default=False, description="Hide the store (a test database)")


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
    stamps: Stamps = field(default_factory=Stamps)
    """Threat stamps from ``stores/<slug>.yaml``."""

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


def collect_stores(unit: Unit, inventory: Inventory | None) -> UnitStores:
    """Merge the introspected stores with the unit's ``stores/*.yaml`` files."""
    result = UnitStores()
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
            )
    folder = unit.folder / STORES_DIR
    if not folder.is_dir():
        return result
    for path in sorted(folder.glob("*.yaml")):
        declared = _load(path, unit, result.diagnostics)
        if declared is None:
            continue
        slug = path.stem
        base = result.stores.get(slug)
        if base is None and declared.type is None:
            result.diagnostics.append(
                Diagnostic(
                    Severity.ERROR,
                    "store-orphan",
                    f"{path.name}: no store {slug!r} in the settings; a manual store "
                    "needs at least `type`",
                    unit.id,
                    path,
                )
            )
            continue
        result.stores[slug] = _merge(unit, slug, base, declared)
    return result


def _merge(unit: Unit, slug: str, base: Store | None, declared: StoreFile) -> Store:
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
            stamps=declared.threats,
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
        hosts=tuple(declared.hosts),
        stamps=declared.threats,
    )


def _load(path: Path, unit: Unit, diagnostics: list[Diagnostic]) -> StoreFile | None:
    try:
        raw = load_yaml(path)
    except (OSError, yaml.YAMLError) as exc:
        diagnostics.append(
            Diagnostic(
                Severity.ERROR, "yaml-error", f"{path.name}: {exc}", unit.id, path
            )
        )
        return None
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
        return None
    try:
        declared = StoreFile.model_validate(raw)
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
        return None
    diagnostics.extend(marker_diagnostics(declared, path, unit.id))
    return declared
