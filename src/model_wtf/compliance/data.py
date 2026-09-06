"""The data inventory: every field of every unit, classified.

The inventory is *virtual*: it is recomputed from the code (Django
introspection) and the knowledge on every call, and nothing generated is
written to disk. What humans write lives in ``<unit>/compliance/data/``:

* ``<app.Model.field>.yaml`` for a field that exists in the code — an
  **override** of any subset of ``pii`` / ``sensitivity`` / ``category``
  with a mandatory ``reason``;
* ``<anything>.yaml`` for an id the code does not know — a **manual item**
  (a store outside the ORM: a bucket, a cache, an external sheet) that must
  be described in full.

Row ids are ``<unit>:<app_label>.<Model>.<field>``; the unit prefix is what
lets the same model shipped in two images be classified independently.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import Field, ValidationError

from model_wtf.compliance.declarations import format_errors
from model_wtf.compliance.knowledge import Dpia, Knowledge  # noqa: TC001 - runtime use
from model_wtf.compliance.report import Diagnostic, Severity
from model_wtf.compliance.schemas import NonEmpty, StrictModel
from model_wtf.compliance.yaml_io import Todo, iter_todo_paths, load_yaml
from model_wtf.introspect.runner import (
    FieldInfo,
    IntrospectionUnavailable,
    Inventory,
    introspect,
    is_django_unit,
)

if TYPE_CHECKING:
    from pathlib import Path

    from model_wtf.compliance.report import Unit

DATA_DIR = "data"
FIELD_ID_PARTS = 3


class Source(StrEnum):
    """Where a row's classification comes from."""

    RULE = "rule"
    OVERRIDE = "override"
    MANUAL = "manual"


class Override(StrictModel):
    """``data/<field id>.yaml`` for a field the code knows."""

    pii: bool | None = None
    sensitivity: str | None = None
    category: str | None = None
    reason: NonEmpty | Todo


class ManualItem(StrictModel):
    """``data/<id>.yaml`` for something the code does not expose."""

    description: NonEmpty | Todo
    pii: bool | Todo
    sensitivity: str | Todo
    category: str | Todo
    reason: NonEmpty | None = Field(default=None, description="Optional rationale")


@dataclass(frozen=True)
class Row:
    """One classified data item.

    ``field`` is ``None`` for manual items. ``assumed`` flags rule defaults
    made in the absence of evidence (JSON, free text, files) that are not
    yet confirmed by an override.
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
    assumed: bool = False
    field: FieldInfo | None = None
    model_module: str | None = None

    @property
    def full_id(self) -> str:
        """``unit:id``."""
        return f"{self.unit}:{self.id}"

    @property
    def fingerprint(self) -> str:
        """Short hash of the facts a review depends on (see KFF-196)."""
        source = (
            self.field.fingerprint_source() if self.field else f"manual|{self.type}"
        )
        return hashlib.sha256(source.encode()).hexdigest()[:8]

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
            "assumed": self.assumed,
            "fingerprint": self.fingerprint,
        }


@dataclass
class UnitData:
    """Everything computed for one unit."""

    unit: Unit
    rows: list[Row] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    introspected: bool = False
    django_version: str | None = None


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
    code_root = unit.code_root or unit.folder.parent
    if unit.discover == "django" or (
        unit.discover == "none" and is_django_unit(code_root)
    ):
        try:
            inventory = introspect(code_root, python=python)
            data.introspected = True
            data.django_version = inventory.django
        except IntrospectionUnavailable as exc:
            data.diagnostics.append(
                Diagnostic(
                    Severity.WARNING, "not-introspectable", str(exc), unit.id, code_root
                )
            )

    overrides = _load_data_files(unit, data.diagnostics)

    known: set[str] = set()
    if inventory is not None:
        for model in inventory.models:
            if model.abstract:
                continue
            for finfo in model.fields:
                item_id = f"{model.label}.{finfo.name}"
                known.add(item_id)
                data.rows.append(
                    _classify(
                        unit.id,
                        item_id,
                        finfo,
                        model.module,
                        knowledge,
                        overrides.get(item_id),
                        data.diagnostics,
                        unit,
                    )
                )

    for item_id, raw in overrides.items():
        if item_id in known:
            continue
        # Not a known field: it must be a complete manual item.
        row = _manual_row(unit, item_id, raw, knowledge, data.diagnostics)
        if row is not None:
            data.rows.append(row)

    data.rows.sort(key=lambda r: r.id)
    return data


def _classify(
    unit_id: str,
    item_id: str,
    finfo: FieldInfo,
    module: str,
    knowledge: Knowledge,
    override_raw: dict[str, Any] | None,
    diagnostics: list[Diagnostic],
    unit: Unit,
) -> Row:
    rule_id, rule = knowledge.classify(finfo)
    pii, level, category = (
        rule.pii,
        knowledge.resolve(rule.sensitivity),
        knowledge.resolve(rule.category),
    )
    source, assumed = Source.RULE, rule.assumed
    if override_raw is not None:
        path = unit.folder / DATA_DIR / f"{item_id}.yaml"
        override = _validate(Override, override_raw, path, diagnostics)
        if override is not None:
            if override.pii is not None:
                pii = override.pii
            if override.sensitivity is not None:
                level = override.sensitivity
            if override.category is not None:
                category = override.category
            _check_vocabulary(level, category, knowledge, path, diagnostics)
            source, assumed = Source.OVERRIDE, False
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
        assumed=assumed,
        field=finfo,
        model_module=module,
    )


def _manual_row(
    unit: Unit,
    item_id: str,
    raw: dict[str, Any],
    knowledge: Knowledge,
    diagnostics: list[Diagnostic],
) -> Row | None:
    path = unit.folder / DATA_DIR / f"{item_id}.yaml"
    if "description" not in raw:
        diagnostics.append(
            Diagnostic(
                Severity.ERROR,
                "data-orphan",
                f"{path.name}: no such field in the code; a manual item needs "
                "description, pii, sensitivity and category",
                unit.id,
                path,
            )
        )
        return None
    item = _validate(ManualItem, raw, path, diagnostics)
    if item is None:
        return None
    level = None if isinstance(item.sensitivity, Todo) else item.sensitivity
    category = None if isinstance(item.category, Todo) else item.category
    if level is not None and category is not None:
        _check_vocabulary(level, category, knowledge, path, diagnostics)
    dpia = (
        knowledge.dpia_for(level, category)
        if level in knowledge.sensitivity and category in knowledge.categories
        else None
    )
    return Row(
        unit=unit.id,
        id=item_id,
        type="manual",
        pii=None if isinstance(item.pii, Todo) else item.pii,
        sensitivity=level,
        category=category,
        dpia=dpia,
        source=Source.MANUAL,
    )


def _load_data_files(
    unit: Unit, diagnostics: list[Diagnostic]
) -> dict[str, dict[str, Any]]:
    """Raw mappings of every ``data/*.yaml`` keyed by file stem."""
    folder = unit.folder / DATA_DIR
    raw_files: dict[str, dict[str, Any]] = {}
    if not folder.is_dir():
        return raw_files
    for path in sorted(folder.glob("*.yaml")):
        try:
            data = load_yaml(path)
        except (OSError, yaml.YAMLError) as exc:
            diagnostics.append(
                Diagnostic(
                    Severity.ERROR, "yaml-error", f"{path.name}: {exc}", unit.id, path
                )
            )
            continue
        if not isinstance(data, dict):
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
        raw_files[path.stem] = data
    return raw_files


def _validate[M: StrictModel](
    model: type[M], raw: dict[str, Any], path: Path, diagnostics: list[Diagnostic]
) -> M | None:
    try:
        instance = model.model_validate(raw)
    except ValidationError as exc:
        diagnostics.extend(
            Diagnostic(
                Severity.ERROR, "schema-error", f"{path.name}: {loc}: {msg}", None, path
            )
            for loc, msg in format_errors(exc)
        )
        return None
    diagnostics.extend(
        Diagnostic(
            Severity.WARNING,
            "todo",
            f"{path.name}: {dotted} is still !todo",
            None,
            path,
        )
        for dotted in iter_todo_paths(instance)
    )
    return instance


def _check_vocabulary(
    level: str,
    category: str,
    knowledge: Knowledge,
    path: Path,
    diagnostics: list[Diagnostic],
) -> None:
    if level not in knowledge.sensitivity:
        diagnostics.append(
            Diagnostic(
                Severity.ERROR,
                "unknown-level",
                f"{path.name}: sensitivity {level!r} is not one of "
                f"{', '.join(knowledge.ordered_levels())}",
                None,
                path,
            )
        )
    if category not in knowledge.categories:
        diagnostics.append(
            Diagnostic(
                Severity.ERROR,
                "unknown-category",
                f"{path.name}: category {category!r} is not one of "
                f"{', '.join(sorted(knowledge.categories))}",
                None,
                path,
            )
        )
