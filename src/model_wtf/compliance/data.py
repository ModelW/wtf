"""The data inventory: every field of every unit, classified.

The inventory is *virtual*: it is recomputed from the code (Django
introspection) and the knowledge on every call, and nothing generated is
stored. What humans write lives in the ``data_items`` table, one row per
``(unit, id)``:

* an ``override`` for a field that exists in the code — any subset of
  ``pii`` / ``sensitivity`` / ``category`` with a mandatory ``reason``;
* a ``manual`` item for an id the code does not know (a store outside the
  ORM: a bucket, a cache, an external sheet) that must be described in
  full;
* a ``contents`` declaration for a JSON-like column (below);
* a ``rights`` block on a ``<app.Model>.*`` glob for a whole model.

Row ids are ``<unit>:<app_label>.<Model>.<field>``; the unit prefix is what
lets the same model shipped in two images be classified independently.

A file field is two things: a column holding a path (technical) and the
store behind it holding the actual bytes (whatever the users uploaded). The
bytes are inventoried as their own synthetic model, ``<app.Model.field>@files``
with a single field ``content``, so they are classified, reviewed and
overridden on their own.

A JSON-like column (``JSONField``, ``ArrayField``, ``HStoreField``; not
Wagtail's ``StreamField``, which is CMS content) is a **container**: one
``pii/sensitivity/category`` triple cannot describe a blob holding a name, an
address and an IBAN. Its row may instead declare ``contents``, one
entry per *kind* of information (not per JSON path), each classified like a
field; every entry becomes a row ``<app.Model.field>@json.<name>`` and the
column's own verdict is **derived** (``pii`` = any, ``sensitivity`` = max,
``category`` = the set). ``unknown_contents`` says whether the list is
exhaustive: ``none`` replaces the rule's presumption, ``possible`` keeps a
warning, ``likely`` folds the presumption back into the derivation.

Every row references the **store** holding it by slug (``db-default``,
``files-default``; see :mod:`model_wtf.compliance.stores`): ORM columns point
at the database the router writes the model to, ``@files`` rows at the file
storage behind the column. Manual items and overrides may set ``store``
explicitly; the slug must exist in the unit's stores and not be ignored.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field, StringConstraints, ValidationError, model_validator
from sqlalchemy import select

from model_wtf.compliance.db import get_db
from model_wtf.compliance.declarations import format_errors
from model_wtf.compliance.knowledge import Dpia, Knowledge
from model_wtf.compliance.report import Diagnostic, Severity, marker_diagnostics
from model_wtf.compliance.rights import Right, RightsSpec
from model_wtf.compliance.schemas import NonEmpty, StrictModel
from model_wtf.compliance.stores import UnitStores, collect_stores
from model_wtf.compliance.tables import DataContentRow, DataItemRow
from model_wtf.compliance.yaml_io import TODO, Marker
from model_wtf.introspect.runner import (
    FieldInfo,
    IntrospectionUnavailable,
    Inventory,
    ModelInfo,
    introspect,
    is_django_unit,
)

if TYPE_CHECKING:
    from model_wtf.compliance.report import Unit

FIELD_ID_PARTS = 3
FILE_STORE_SUFFIX = "@files"
FILE_STORE_FIELD = "content"
FILE_INTERNAL_TYPES = frozenset({"FileField", "ImageField"})
JSON_SUFFIX = "@json"
JSON_CONTENT_TYPE = "JsonContent"
CONTAINER_INTERNAL_TYPES = frozenset({"JSONField", "ArrayField", "HStoreField"})
NOT_CONTAINER_TYPES = frozenset({"StreamField"})
CONTENT_NAME = r"^[a-z0-9_]+$"
CATEGORY_JOIN = "+"


class Source(StrEnum):
    """Where a row's classification comes from."""

    RULE = "rule"
    KNOWN = "known"
    """Fixed library verdict (a password hash is a password hash): reviewed."""
    LIBRARY = "library"
    """Library default resting on an assumption: applied, but still to confirm."""
    OVERRIDE = "override"
    MANUAL = "manual"
    DERIVED = "derived"
    """A container column whose verdict is computed from its declared contents."""


class Unknown(StrEnum):
    """How exhaustive a ``contents`` declaration is."""

    NONE = "none"
    """Every write site was read; the list is complete."""
    POSSIBLE = "possible"
    """Some writes are dynamic; other things may end up in the blob."""
    LIKELY = "likely"
    """The blob is mostly opaque; the rule's presumption stays in force."""


def is_container(finfo: FieldInfo) -> bool:
    """Whether a field is a JSON-like blob that can declare ``contents``."""
    return (
        finfo.internal_type in CONTAINER_INTERNAL_TYPES
        and finfo.type not in NOT_CONTAINER_TYPES
    )


class Content(StrictModel):
    """One kind of information held in a container column."""

    pii: bool | Marker
    sensitivity: str | Marker
    category: str | Marker


class Contents(StrictModel):
    """A ``contents`` row for a container column: what the blob holds."""

    contents: dict[Annotated[str, StringConstraints(pattern=CONTENT_NAME)], Content]
    unknown_contents: Unknown
    reason: NonEmpty | Marker


class Override(StrictModel):
    """An ``override`` row for a field the code knows."""

    pii: bool | None = None
    sensitivity: str | None = None
    category: str | None = None
    store: str | None = None
    """Slug of the store holding the value, when the settings get it wrong."""
    reason: NonEmpty | Marker | None = None
    """Why the rule was wrong. Optional when the row only carries ``rights``."""
    rights: RightsSpec | None = None
    """Exemptions or observed gaps per right (see :mod:`rights`)."""

    @model_validator(mode="after")
    def _reason_unless_rights_only(self) -> Override:
        given = (self.pii, self.sensitivity, self.category, self.store)
        classifies = any(v is not None for v in given)
        if classifies and self.reason is None:
            msg = "reason: required when the row changes the classification"
            raise ValueError(msg)
        return self


class RightsOnly(StrictModel):
    """A ``<app.Model>.*`` row: a rights block for every field of a model."""

    rights: RightsSpec


class ManualItem(StrictModel):
    """A ``manual`` row for something the code does not expose."""

    description: NonEmpty | Marker
    pii: bool | Marker
    sensitivity: str | Marker
    category: str | Marker
    store: str | Marker | None = None
    """Slug of the store holding the item (a ``stores`` row declares external ones)."""
    transient: bool = Field(
        default=False,
        description="Processed but never kept by this project (a card number "
        "forwarded, a query parameter): no storage, so no storage-side rights",
    )
    reason: NonEmpty | None = Field(default=None, description="Optional rationale")
    rights: RightsSpec | None = None


@dataclass(frozen=True)
class Row:
    """One classified data item.

    ``field`` is ``None`` for manual items.
    """

    unit: str
    id: str
    type: str
    pii: bool | None
    sensitivity: str | None
    category: str | None
    dpia: Dpia | None
    source: Source
    rule: str | None = None
    field: FieldInfo | None = None
    model_module: str | None = None
    model_file: str | None = None
    """Absolute path of the module defining the model, from introspection."""
    model_bases: tuple[str, ...] = ()
    """Library models in the MRO (``wagtailcore.Page`` for a page type)."""
    store: str | None = None
    """Slug of the store holding the value (``db-default``, ``files-default``);
    ``None`` when unknown (manual item without ``store``)."""
    contents: tuple[str, ...] = ()
    """Names of the declared contents (container columns only)."""
    assumption: str | None = None
    """What a library default takes for granted (source ``library``)."""
    check: str | None = None
    """What to look at in this project to confirm or refute ``assumption``."""
    unknown_contents: Unknown | None = None
    """Exhaustiveness of ``contents`` (container columns with a declaration)."""
    rights: RightsSpec | None = None
    """Exemptions / observed gaps, from the item's row or the model glob row."""
    transient: bool = False
    """Manual item never kept by this project; only transfers matter."""

    @property
    def full_id(self) -> str:
        """``unit:id``."""
        return f"{self.unit}:{self.id}"

    @property
    def fingerprint(self) -> str:
        """Short hash of what a review actually confirmed.

        Two things can invalidate a review: the field changed (type,
        nullability, relation) or the *conclusion* changed because the rule
        set evolved (another rule now fires, or the same rule yields another
        classification). Both are folded in, so a knowledge upgrade re-opens
        exactly the items whose verdict moved.
        """
        facts = self.field.fingerprint_source() if self.field else f"manual|{self.type}"
        verdict = f"{self.rule}|{self.pii}|{self.sensitivity}|{self.category}"
        if self.contents:
            verdict += f"|{','.join(self.contents)}|{self.unknown_contents}"
        return hashlib.sha256(f"{facts}#{verdict}".encode()).hexdigest()[:8]

    def to_dict(self) -> dict[str, Any]:
        """JSON-friendly form for ``--format json`` and the MCP tools."""
        return {
            "unit": self.unit,
            "id": self.id,
            "type": self.type,
            "pii": self.pii,
            "sensitivity": self.sensitivity,
            "category": self.category,
            "dpia": self.dpia.value if self.dpia else None,
            "source": self.source.value,
            "rule": self.rule,
            "store": self.store,
            "contents": list(self.contents),
            "assumption": self.assumption,
            "check": self.check,
            "unknown_contents": self.unknown_contents.value
            if self.unknown_contents
            else None,
            "fingerprint": self.fingerprint,
        }


@dataclass
class UnitData:
    """Everything computed for one unit."""

    unit: Unit
    rows: list[Row] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    stores: UnitStores = field(default_factory=UnitStores)
    introspected: bool = False
    django_version: str | None = None
    sys_path: list[str] = field(default_factory=list)
    """Import roots of the unit's interpreter (for agent read access)."""


def parse_full_id(value: str, units: list[Unit]) -> tuple[str, str]:
    """Split ``unit:id``; the prefix may be omitted when there is one unit."""
    if ":" in value:
        unit_id, item_id = value.split(":", 1)
        if not any(u.id == unit_id for u in units):
            msg = f"unknown unit {unit_id!r}"
            raise ValueError(msg)
        return unit_id, item_id
    if len(units) == 1:
        return units[0].id, value
    msg = "several units declared; prefix the id with `<unit>:`"
    raise ValueError(msg)


def collect_unit(
    unit: Unit, knowledge: Knowledge, *, python: str | None = None
) -> UnitData:
    """Introspect ``unit`` (when it is Django), apply rules and overrides.

    Never raises for a non-Django or non-introspectable unit: those yield
    an empty inventory plus a warning. Introspection *failures* (the script
    crashed) do propagate — they are tool errors, not declarations.
    """
    data = UnitData(unit)
    inventory: Inventory | None = None
    code_root = unit.code_root
    if unit.discover == "django" or (
        unit.discover == "none" and is_django_unit(code_root)
    ):
        try:
            inventory = introspect(code_root, python=python)
            data.introspected = True
            data.django_version = inventory.django
            data.sys_path = inventory.sys_path
        except IntrospectionUnavailable as exc:
            data.diagnostics.append(
                Diagnostic(
                    Severity.WARNING, "not-introspectable", str(exc), unit.id, code_root
                )
            )

    data.stores = collect_stores(unit, inventory)
    data.diagnostics.extend(data.stores.diagnostics)
    overrides = load_data_items(unit.id)
    model_rights = _pop_model_rights(unit, overrides, data.diagnostics)

    known: set[str] = set()
    if inventory is not None:
        for model in inventory.models:
            if model.abstract:
                continue
            for item_id, finfo in _model_items(model):
                known.add(item_id)
                content_rows = _pop_content_rows(item_id, overrides)
                known.update(content_rows)
                data.rows.extend(
                    _rows_for(
                        unit,
                        item_id,
                        finfo,
                        model,
                        knowledge,
                        overrides.get(item_id),
                        data.diagnostics,
                        content_rows,
                    )
                )

    for item_id, raw in overrides.items():
        if item_id in known:
            continue
        # Not a known field: it must be a complete manual item.
        row = _manual_row(unit, item_id, raw, knowledge, data.diagnostics)
        if row is not None:
            data.rows.append(row)

    _apply_library_rights(data, knowledge)
    _apply_model_rights(unit, data, model_rights)
    data.rows.sort(key=lambda r: r.id)
    _check_store_references(data)
    return data


def item_label(unit_id: str, item_id: str) -> str:
    """How a data row is named in diagnostics (``data/api:shop.User.email``)."""
    return f"data/{unit_id}:{item_id}"


def _pop_model_rights(
    unit: Unit, overrides: dict[str, dict[str, Any]], diagnostics: list[Diagnostic]
) -> dict[str, RightsSpec]:
    """Take the ``<app.Model>.*`` rows out of ``overrides``; ``{label: rights}``."""
    out: dict[str, RightsSpec] = {}
    for stem in [s for s in overrides if s.endswith(".*")]:
        raw = overrides.pop(stem)
        spec = _validate(RightsOnly, raw, item_label(unit.id, stem), diagnostics)
        if spec is not None:
            out[stem[:-2]] = spec.rights
    return out


def _split_id(item_id: str) -> tuple[str, str]:
    """``cms.CustomDocument.file@files.content`` → ``(cms.CustomDocument, file)``.

    The ``@files`` / ``@json`` suffix hangs off the field, so it is cut first;
    the model label is everything before the field.
    """
    base = item_id.split("@", 1)[0]
    label, _, field_name = base.rpartition(".")
    return label, field_name


def _apply_library_rights(data: UnitData, knowledge: Knowledge) -> None:
    """Rights a library model ships for its own personal fields.

    Lowest precedence: the project's glob file and item file both win, right
    by right. Keyed by model label, so a project override of the
    classification does not lose the framework's rights story.
    """
    for index, row in enumerate(data.rows):
        if not row.pii:
            continue
        label, field_name = _split_id(row.id)
        block = knowledge.library_rights(label)
        if not block:
            # A project model deriving from a library one (a Wagtail page
            # type) inherits the story for the columns the base defines.
            for base in row.model_bases:
                model = knowledge.library.get(base)
                if model is not None and model.rights and field_name in model.fields:
                    block = model.rights
                    break
        if not block:
            continue
        spec = RightsSpec.model_validate(block)
        merged = spec if row.rights is None else _merge_rights(spec, row.rights)
        data.rows[index] = replace(row, rights=merged)


def _apply_model_rights(
    unit: Unit, data: UnitData, model_rights: dict[str, RightsSpec]
) -> None:
    """Glob rights apply to every field of the model without its own block.

    Rights on a non-personal item are meaningless (nothing to exempt), so
    the glob only lands on ``pii`` rows; an item row with its own ``rights``
    wins over the glob, right by right.
    """
    if not model_rights:
        return
    for index, row in enumerate(data.rows):
        label, _ = _split_id(row.id)
        spec = model_rights.get(label)
        if spec is None or not row.pii:
            continue
        merged = spec if row.rights is None else _merge_rights(spec, row.rights)
        data.rows[index] = replace(row, rights=merged)
    for label in model_rights:
        if not any(r.id.startswith(f"{label}.") for r in data.rows):
            data.diagnostics.append(
                Diagnostic(
                    Severity.ERROR,
                    "data-ref-unknown",
                    f"{item_label(unit.id, label + '.*')}: no model {label!r} "
                    f"in unit {unit.id}",
                    unit.id,
                )
            )


def _merge_rights(base: RightsSpec, over: RightsSpec) -> RightsSpec:
    values = {
        r.value: over.get(r) if over.get(r) is not None else base.get(r) for r in Right
    }
    return RightsSpec.model_validate(values)


def _check_store_references(data: UnitData) -> None:
    """Every ``store`` a row names must exist and not be hidden."""
    for row in data.rows:
        if row.store is None or row.source not in (Source.OVERRIDE, Source.MANUAL):
            continue
        store = data.stores.get(row.store)
        label = item_label(data.unit.id, row.id)
        if store is None:
            slugs = ", ".join(s.slug for s in data.stores.visible()) or "none"
            data.diagnostics.append(
                Diagnostic(
                    Severity.ERROR,
                    "store-unknown",
                    f"{label}: store {row.store!r} is not declared; known: {slugs}",
                    data.unit.id,
                )
            )
        elif store.ignore:
            data.diagnostics.append(
                Diagnostic(
                    Severity.ERROR,
                    "store-ignored-referenced",
                    f"{label}: store {row.store!r} is ignored but referenced",
                    data.unit.id,
                )
            )


def _model_items(model: ModelInfo) -> list[tuple[str, FieldInfo]]:
    """``(item id, field)`` for every column plus the store behind file columns."""
    items: list[tuple[str, FieldInfo]] = []
    for finfo in model.fields:
        item_id = f"{model.label}.{finfo.name}"
        items.append((item_id, finfo))
        if finfo.internal_type in FILE_INTERNAL_TYPES:
            store_id = f"{item_id}{FILE_STORE_SUFFIX}.{FILE_STORE_FIELD}"
            items.append((store_id, file_store_field(finfo)))
    return items


def file_store_field(column: FieldInfo) -> FieldInfo:
    """The synthetic ``content`` field of the store behind a file column.

    Typed ``FileStore`` so the rules can address it (``file`` rule) while
    the column itself falls through to the path/technical rules.
    """
    return FieldInfo(
        name=FILE_STORE_FIELD,
        type="FileStore",
        internal_type="FileStore",
        null=column.null,
        blank=column.blank,
        storage=column.storage,
    )


def _classify(
    unit_id: str,
    item_id: str,
    finfo: FieldInfo,
    model: ModelInfo,
    knowledge: Knowledge,
    override_raw: dict[str, Any] | None,
    diagnostics: list[Diagnostic],
    unit: Unit,
) -> Row:
    rule_id, rule = knowledge.classify(finfo)
    field_name = _library_field_name(item_id, model)
    known = knowledge.known_field(model.label, field_name)
    if known is None:
        # A project model deriving from a library one (``cms.CustomDocument``
        # from ``wagtaildocs.AbstractDocument``) inherits the verdicts for
        # the columns the base defines — listed fields only, never the
        # base's ``fields_default`` (the project's own columns are its own).
        for base in model.bases:
            known = knowledge.known_field(base, field_name, listed_only=True)
            if known is not None:
                break
    pii, level, category = (
        rule.pii,
        knowledge.resolve(rule.sensitivity),
        knowledge.resolve(rule.category),
    )
    source = Source.RULE
    store = _store_slug(finfo, model)
    assumption = check = None
    rights: RightsSpec | None = None
    if known is not None:
        # Library verdict: applied after the rule, before any repo override.
        # Fixed ones need no review; assumed ones stay pending with a caption.
        pii, level, category = known.pii, known.sensitivity, known.category
        source = Source.KNOWN if known.fixed else Source.LIBRARY
        if not known.fixed:
            assumption, check = known.assumption, known.check
    if override_raw is not None:
        label = item_label(unit.id, item_id)
        override = _validate(Override, override_raw, label, diagnostics)
        if override is not None:
            pii = override.pii if override.pii is not None else pii
            level = override.sensitivity or level
            category = override.category or category
            store = override.store or store
            _check_vocabulary(level, category, knowledge, label, diagnostics)
            rights = override.rights
            if override.reason is not None or rights is None:
                source = Source.OVERRIDE
            if rights is not None and not pii:
                diagnostics.append(
                    Diagnostic(
                        Severity.ERROR,
                        "rights-on-non-personal",
                        f"{label}: rights declared on a non-personal item "
                        "(nothing to exempt)",
                        unit.id,
                    )
                )
    dpia = (
        knowledge.dpia_for(level, category)
        if level in knowledge.sensitivity and category in knowledge.categories
        else None
    )
    return Row(
        unit=unit_id,
        id=item_id,
        type=finfo.type,
        pii=pii,
        sensitivity=level,
        category=category,
        dpia=dpia,
        source=source,
        rule=rule_id,
        field=finfo,
        model_module=model.module,
        model_file=model.file,
        model_bases=tuple(model.bases),
        store=store,
        assumption=assumption,
        check=check,
        rights=rights,
    )


def _rows_for(
    unit: Unit,
    item_id: str,
    finfo: FieldInfo,
    model: ModelInfo,
    knowledge: Knowledge,
    raw: dict[str, Any] | None,
    diagnostics: list[Diagnostic],
    content_rows: dict[str, dict[str, Any]] | None = None,
) -> list[Row]:
    """Rows for one column: itself, or itself plus its declared contents.

    ``content_rows`` are the ``<field>@json.<name>`` item rows of the column
    (rights blocks on a declared content); they only make sense with a
    ``contents`` declaration and are reported otherwise.
    """
    content_rows = content_rows or {}
    if raw is not None and "contents" in raw:
        if is_container(finfo):
            return _container_rows(
                unit, item_id, finfo, model, knowledge, raw, diagnostics, content_rows
            )
        diagnostics.append(
            Diagnostic(
                Severity.ERROR,
                "schema-error",
                f"{item_label(unit.id, item_id)}: `contents` is only for JSON-like "
                f"columns; {item_id} is a {finfo.type}",
                unit.id,
            )
        )
        raw = None
    for content_id in content_rows:
        diagnostics.append(
            Diagnostic(
                Severity.ERROR,
                "data-orphan",
                f"{item_label(unit.id, content_id)}: no `contents` declaration on "
                f"{item_id}; declare the column's contents first",
                unit.id,
            )
        )
    return [
        _classify(unit.id, item_id, finfo, model, knowledge, raw, diagnostics, unit)
    ]


def _container_rows(
    unit: Unit,
    item_id: str,
    finfo: FieldInfo,
    model: ModelInfo,
    knowledge: Knowledge,
    raw: dict[str, Any],
    diagnostics: list[Diagnostic],
    content_rows: dict[str, dict[str, Any]],
) -> list[Row]:
    """A container column with a ``contents`` row: its items plus the derived column.

    The column is first classified by the rules (so ``rule`` and the
    presumption are known), then replaced by the derivation over the items.
    A ``<field>@json.<name>`` row in ``content_rows`` carries the rights
    block of that content (a retention gap observed on one key of the blob).
    """
    column = _classify(
        unit.id, item_id, finfo, model, knowledge, None, diagnostics, unit
    )
    label = item_label(unit.id, item_id)
    declared = _validate(Contents, raw, label, diagnostics)
    if declared is None:
        return [column]
    items: list[Row] = []
    for name, content in declared.contents.items():
        level = None if isinstance(content.sensitivity, Marker) else content.sensitivity
        category = None if isinstance(content.category, Marker) else content.category
        if level is not None and category is not None:
            _check_vocabulary(level, category, knowledge, label, diagnostics)
        content_id = f"{item_id}{JSON_SUFFIX}.{name}"
        pii = None if isinstance(content.pii, Marker) else content.pii
        items.append(
            Row(
                unit=unit.id,
                id=content_id,
                type=JSON_CONTENT_TYPE,
                pii=pii,
                sensitivity=level,
                category=category,
                dpia=_dpia(knowledge, level, category),
                source=Source.OVERRIDE,
                rule=column.rule,
                field=finfo,
                model_module=model.module,
                model_file=model.file,
                store=column.store,
                rights=_content_rights(
                    unit, content_id, pii, content_rows.get(content_id), diagnostics
                ),
            )
        )
    declared_ids = {r.id for r in items}
    for content_id in content_rows:
        if content_id not in declared_ids:
            diagnostics.append(
                Diagnostic(
                    Severity.ERROR,
                    "data-ref-unknown",
                    f"{item_label(unit.id, content_id)}: {item_id} declares no "
                    f"content named {content_id.rsplit('.', 1)[1]!r}",
                    unit.id,
                )
            )
    if declared.unknown_contents is Unknown.POSSIBLE:
        diagnostics.append(
            Diagnostic(
                Severity.WARNING,
                "json-unknown-contents",
                f"{label}: other things may be written into {item_id} "
                "(unknown_contents: possible)",
                unit.id,
            )
        )
    return [derive_column(column, items, declared.unknown_contents, knowledge), *items]


def _pop_content_rows(
    item_id: str, overrides: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """Take the ``<item_id>@json.<name>`` rows out of ``overrides``."""
    prefix = f"{item_id}{JSON_SUFFIX}."
    return {k: overrides.pop(k) for k in [k for k in overrides if k.startswith(prefix)]}


def _content_rights(
    unit: Unit,
    content_id: str,
    pii: bool | None,
    raw: dict[str, Any] | None,
    diagnostics: list[Diagnostic],
) -> RightsSpec | None:
    """The rights block of a declared content, from its own ``override`` row.

    Only ``rights`` is meaningful there: the classification of a content
    lives in the column's ``contents`` declaration.
    """
    if raw is None:
        return None
    label = item_label(unit.id, content_id)
    override = _validate(Override, raw, label, diagnostics)
    if override is None:
        return None
    if any(
        v is not None for v in (override.pii, override.sensitivity, override.category)
    ):
        diagnostics.append(
            Diagnostic(
                Severity.ERROR,
                "schema-error",
                f"{label}: a content is classified by the column's `contents` "
                "declaration; only `rights` applies to a @json row",
                unit.id,
            )
        )
    if override.rights is not None and not pii:
        diagnostics.append(
            Diagnostic(
                Severity.ERROR,
                "rights-on-non-personal",
                f"{label}: rights declared on a non-personal item (nothing to exempt)",
                unit.id,
            )
        )
    return override.rights


def derive_column(
    column: Row, items: list[Row], unknown: Unknown, knowledge: Knowledge
) -> Row:
    """The container's verdict from its contents.

    ``pii`` is true if any item is; ``sensitivity`` is the highest rank;
    ``category`` is the sorted set joined with ``+``; DPIA is the max. With
    ``unknown_contents: likely`` the rule's own presumption is one more item.
    """
    pool = list(items)
    if unknown is Unknown.LIKELY:
        pool.append(column)
    if not pool:
        # Nothing declared and nothing presumed: an empty, harmless blob.
        return replace(
            column,
            pii=False,
            sensitivity=knowledge.resolve("internal"),
            category=knowledge.resolve("technical"),
            dpia=Dpia.NEVER,
            source=Source.DERIVED,
            contents=(),
            unknown_contents=unknown,
        )
    piis = [r.pii for r in pool]
    pii: bool | None = True if any(piis) else (False if None not in piis else None)
    levels = [r.sensitivity for r in pool if r.sensitivity in knowledge.sensitivity]
    level = (
        max(levels, key=lambda lv: knowledge.sensitivity[lv].rank) if levels else None
    )
    categories = sorted({r.category for r in pool if r.category})
    category = CATEGORY_JOIN.join(categories) if categories else None
    dpias = [r.dpia for r in pool if r.dpia is not None]
    dpia = max(dpias, key=lambda d: d.rank) if dpias else None
    return replace(
        column,
        pii=pii,
        sensitivity=level,
        category=category,
        dpia=dpia,
        source=Source.DERIVED,
        contents=tuple(r.id.rsplit(".", 1)[1] for r in items),
        unknown_contents=unknown,
    )


def _dpia(knowledge: Knowledge, level: str | None, category: str | None) -> Dpia | None:
    if level in knowledge.sensitivity and category in knowledge.categories:
        return knowledge.dpia_for(level, category)
    return None


def _library_field_name(item_id: str, model: ModelInfo) -> str:
    """``app.Model.avatar@files.content`` → ``avatar@files.content``."""
    return item_id[len(model.label) + 1 :]


def _store_slug(finfo: FieldInfo, model: ModelInfo) -> str | None:
    """File storage slug for a ``@files`` row, else the model's database slug."""
    if finfo.type == "FileStore":
        return finfo.storage.store if finfo.storage else None
    return model.database.store if model.database else None


def _manual_row(
    unit: Unit,
    item_id: str,
    raw: dict[str, Any],
    knowledge: Knowledge,
    diagnostics: list[Diagnostic],
) -> Row | None:
    label = item_label(unit.id, item_id)
    if "description" not in raw:
        diagnostics.append(
            Diagnostic(
                Severity.ERROR,
                "data-orphan",
                f"{label}: no such field in the code; a manual item needs "
                "description, pii, sensitivity and category",
                unit.id,
            )
        )
        return None
    item = _validate(ManualItem, raw, label, diagnostics)
    if item is None:
        return None
    level = None if isinstance(item.sensitivity, Marker) else item.sensitivity
    category = None if isinstance(item.category, Marker) else item.category
    if level is not None and category is not None:
        _check_vocabulary(level, category, knowledge, label, diagnostics)
    dpia = (
        knowledge.dpia_for(level, category)
        if level in knowledge.sensitivity and category in knowledge.categories
        else None
    )
    return Row(
        unit=unit.id,
        id=item_id,
        type="manual",
        pii=None if isinstance(item.pii, Marker) else item.pii,
        sensitivity=level,
        category=category,
        dpia=dpia,
        source=Source.MANUAL,
        store=None if isinstance(item.store, Marker) else item.store,
        rights=item.rights,
        transient=item.transient,
    )


def _item_raw(row: DataItemRow) -> dict[str, Any]:
    """A ``data_items`` row as the mapping its schema validates.

    The row's ``kind`` decides which keys are meaningful; whatever is set
    is passed through so a stray value is reported by the schema, not
    silently dropped.
    """
    raw: dict[str, Any] = {}
    if row.kind == "contents":
        raw["contents"] = {
            c.name: {"pii": c.pii, "sensitivity": c.sensitivity, "category": c.category}
            for c in row.contents
        }
        raw["unknown_contents"] = row.unknown_contents
        raw["reason"] = row.reason if row.reason is not None else TODO
        return raw
    for key in ("description", "pii", "sensitivity", "category", "store", "reason"):
        value = getattr(row, key)
        if value is not None:
            raw[key] = value
    if row.transient:
        raw["transient"] = True
    if row.rights is not None:
        raw["rights"] = row.rights
    return raw


def load_data_items(unit_id: str) -> dict[str, dict[str, Any]]:
    """Raw mappings of every ``data_items`` row of a unit keyed by item id."""
    with get_db() as db:
        rows = db.scalars(
            select(DataItemRow)
            .where(DataItemRow.unit == unit_id)
            .order_by(DataItemRow.id)
        ).all()
        return {row.id: _item_raw(row) for row in rows}


def _validate[M: StrictModel](
    model: type[M], raw: dict[str, Any], label: str, diagnostics: list[Diagnostic]
) -> M | None:
    try:
        instance = model.model_validate(raw)
    except ValidationError as exc:
        diagnostics.extend(
            Diagnostic(Severity.ERROR, "schema-error", f"{label}: {loc}: {msg}", None)
            for loc, msg in format_errors(exc)
        )
        return None
    # A marker inside ``rights`` is reported per item by the rights derivation
    # (it knows which items and which activities); the row-level line would
    # say the same thing twice.
    diagnostics.extend(
        d
        for d in marker_diagnostics(instance, label, None)
        if not (d.subject or "").split("#", 1)[-1].startswith("rights.")
    )
    return instance


def _check_vocabulary(
    level: str,
    category: str,
    knowledge: Knowledge,
    label: str,
    diagnostics: list[Diagnostic],
) -> None:
    if level not in knowledge.sensitivity:
        diagnostics.append(
            Diagnostic(
                Severity.ERROR,
                "unknown-level",
                f"{label}: sensitivity {level!r} is not one of "
                f"{', '.join(knowledge.ordered_levels())}",
                None,
            )
        )
    if category not in knowledge.categories:
        diagnostics.append(
            Diagnostic(
                Severity.ERROR,
                "unknown-category",
                f"{label}: category {category!r} is not one of "
                f"{', '.join(sorted(knowledge.categories))}",
                None,
            )
        )


def parse_content_entry(
    entry: str, knowledge: Knowledge
) -> tuple[str, tuple[bool, str, str]]:
    """``name=yes,personal,contact`` → ``("name", (True, "personal", "contact"))``.

    Raises
    ------
    ValueError
        Malformed entry or vocabulary not in the knowledge.
    """
    name, sep, spec = entry.partition("=")
    parts = [p.strip() for p in spec.split(",")]
    if not sep or not re.fullmatch(CONTENT_NAME, name) or len(parts) != 3:
        msg = f"{entry!r}: expected name=pii,sensitivity,category (name: [a-z0-9_]+)"
        raise ValueError(msg)
    pii_text, level, category = parts
    if pii_text.lower() not in ("yes", "no", "true", "false"):
        msg = f"{entry!r}: pii must be yes/no"
        raise ValueError(msg)
    if level not in knowledge.sensitivity:
        msg = f"{entry!r}: unknown sensitivity {level!r}; levels: " + ", ".join(
            knowledge.ordered_levels()
        )
        raise ValueError(msg)
    if category not in knowledge.categories:
        msg = f"{entry!r}: unknown category {category!r}; categories: " + ", ".join(
            sorted(knowledge.categories)
        )
        raise ValueError(msg)
    return name, (pii_text.lower() in ("yes", "true"), level, category)


# ---------------------------------------------------------------------------
# writing
# ---------------------------------------------------------------------------


def has_data_item(unit_id: str, item_id: str) -> bool:
    """Whether a row exists for ``(unit, id)``."""
    with get_db() as db:
        return db.get(DataItemRow, (unit_id, item_id)) is not None


def write_contents(
    unit: Unit,
    local_id: str,
    contents: dict[str, tuple[bool, str, str]],
    *,
    unknown: Unknown,
    reason: str | None,
) -> bool:
    """Write a ``contents`` declaration; ``False`` when a row already exists."""
    with get_db() as db:
        if db.get(DataItemRow, (unit.id, local_id)) is not None:
            return False
        row = DataItemRow(
            unit=unit.id,
            id=local_id,
            kind="contents",
            unknown_contents=unknown.value,
            reason=reason if reason else TODO,
        )
        row.contents = [
            DataContentRow(
                unit=unit.id,
                item_id=local_id,
                name=name,
                position=index,
                pii=pii,
                sensitivity=level,
                category=category,
            )
            for index, (name, (pii, level, category)) in enumerate(contents.items())
        ]
        db.add(row)
    return True


def write_override(
    unit: Unit,
    local_id: str,
    *,
    pii: bool | None,
    sensitivity: str | None,
    category: str | None,
    reason: str | Marker | None,
    store: str | None = None,
) -> bool:
    """Write an ``override`` row; ``False`` when one already exists."""
    with get_db() as db:
        if db.get(DataItemRow, (unit.id, local_id)) is not None:
            return False
        db.add(
            DataItemRow(
                unit=unit.id,
                id=local_id,
                kind="override",
                pii=pii,
                sensitivity=sensitivity,
                category=category,
                store=store,
                reason=reason if reason else TODO,
            )
        )
    return True


def write_manual(
    unit: Unit,
    item_id: str,
    *,
    description: str | Marker,
    pii: bool | Marker,
    sensitivity: str | Marker,
    category: str | Marker,
    store: str | Marker | None = None,
    transient: bool = False,
    reason: str | None = None,
) -> bool:
    """Write a ``manual`` row; ``False`` when one already exists."""
    with get_db() as db:
        if db.get(DataItemRow, (unit.id, item_id)) is not None:
            return False
        db.add(
            DataItemRow(
                unit=unit.id,
                id=item_id,
                kind="manual",
                description=description,
                pii=pii,
                sensitivity=sensitivity,
                category=category,
                store=store,
                transient=transient,
                reason=reason,
            )
        )
    return True


def set_rights(unit_id: str, item_id: str, rights: dict[str, Any]) -> None:
    """Set the ``rights`` block of an item row, creating a rights-only row
    (``override`` for a field, ``rights`` for a ``<app.Model>.*`` glob) when
    the item has none yet. Every other column is left as it is."""
    with get_db() as db:
        row = db.get(DataItemRow, (unit_id, item_id))
        if row is None:
            kind = "rights" if item_id.endswith(".*") else "override"
            row = DataItemRow(unit=unit_id, id=item_id, kind=kind)
            db.add(row)
        row.rights = rights


def override_reason(unit_id: str, item_id: str) -> str | None:
    """The ``reason`` a human gave on an item row, when it is text."""
    with get_db() as db:
        row = db.get(DataItemRow, (unit_id, item_id))
    reason = row.reason if row is not None else None
    return reason if isinstance(reason, str) else None
