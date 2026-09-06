"""Activities: GDPR processing activities, the Art. 30 register's rows.

An activity groups **touchpoints** (front routes, API endpoints, tasks,
admin screens) under one *purpose* with one legal basis. It is the only
object here with real legal fields; everything else about it is **derived**
from the touchpoints it lists: the data items they handle, hence the
categories, the stores, the maximum sensitivity and the DPIA trigger, and
the units involved.

Activities live at the repository root, ``compliance/activities/<slug>.yaml``,
because they span units::

    name: Order fulfilment
    purpose: Take, pay and deliver restaurant orders
    legal_basis: contract
    data_subjects: [customers, restaurant staff]
    touchpoints: [front:/checkout, api:checkout, api:task:orders.send_receipt]
    recipients: [stripe]          # party ids; optional
    retention: 10 years (accounting)
    controller: fah               # defaults to app.yaml's; processor likewise

Any legal field may be ``!todo``. "Process" is not used anywhere here: pytm
reserves it for a running component.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import Field, ValidationError

from model_wtf.compliance.declarations import format_errors
from model_wtf.compliance.report import Diagnostic, Severity
from model_wtf.compliance.schemas import NonEmpty, Slug, StrictModel
from model_wtf.compliance.yaml_io import Todo, iter_todo_paths, load_yaml

if TYPE_CHECKING:
    from pathlib import Path

    from model_wtf.compliance.data import Row
    from model_wtf.compliance.knowledge import Dpia, Knowledge
    from model_wtf.compliance.touchpoints import Touchpoint

ACTIVITIES_DIR = "activities"


class LegalBasis(StrEnum):
    """Art. 6(1) GDPR."""

    CONSENT = "consent"
    CONTRACT = "contract"
    LEGAL_OBLIGATION = "legal_obligation"
    VITAL_INTERESTS = "vital_interests"
    PUBLIC_TASK = "public_task"
    LEGITIMATE_INTERESTS = "legitimate_interests"


class ActivityFile(StrictModel):
    """``activities/<slug>.yaml``."""

    name: NonEmpty | Todo
    purpose: NonEmpty | Todo
    legal_basis: LegalBasis | Todo
    touchpoints: list[str] = Field(default_factory=list)
    data_subjects: list[NonEmpty] | Todo = Field(default_factory=list)
    recipients: list[Slug] = Field(default_factory=list)
    retention: NonEmpty | Todo | None = None
    controller: Slug | Todo | None = None
    processor: Slug | Todo | None = None
    description: NonEmpty | None = None


@dataclass
class Derived:
    """What an activity's touchpoints imply."""

    data: list[str] = field(default_factory=list)
    """Full ids of the data items handled, sorted."""
    pii_data: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    stores: list[str] = field(default_factory=list)
    """``unit:slug`` of every store holding one of the items."""
    units: list[str] = field(default_factory=list)
    max_sensitivity: str | None = None
    dpia: Dpia | None = None
    recipients: dict[str, list[str]] = field(default_factory=dict)
    """Party id → data items exported to it by the touchpoints (derived, on
    top of the declared ``recipients`` list)."""


@dataclass
class Activity:
    """One activity with its derivation."""

    slug: str
    spec: ActivityFile
    path: Path
    derived: Derived = field(default_factory=Derived)
    touchpoints: list[Touchpoint] = field(default_factory=list)
    """Resolved touchpoints (unknown references are reported, not kept)."""

    def to_dict(self) -> dict[str, Any]:
        """JSON form (``!todo`` values become ``null``)."""
        spec = {
            key: None if isinstance(value, Todo) else value
            for key, value in self.spec.model_dump(mode="python").items()
        }
        spec["legal_basis"] = (
            spec["legal_basis"].value
            if isinstance(spec["legal_basis"], LegalBasis)
            else spec["legal_basis"]
        )
        return {
            "slug": self.slug,
            **spec,
            "derived": {
                "data": self.derived.data,
                "pii_data": self.derived.pii_data,
                "categories": self.derived.categories,
                "stores": self.derived.stores,
                "units": self.derived.units,
                "max_sensitivity": self.derived.max_sensitivity,
                "dpia": self.derived.dpia.value if self.derived.dpia else None,
                "recipients": self.derived.recipients,
            },
        }


@dataclass
class Activities:
    """Every activity of the repository plus loading diagnostics."""

    items: dict[str, Activity] = field(default_factory=dict)
    diagnostics: list[Diagnostic] = field(default_factory=list)

    def holding(self, data_ref: str) -> list[Activity]:
        """Activities whose derived data includes ``unit:id``."""
        return [a for a in self.items.values() if data_ref in a.derived.data]

    def of_touchpoint(self, full_id: str) -> list[Activity]:
        """Activities listing the touchpoint ``unit:id``."""
        return [a for a in self.items.values() if full_id in a.spec.touchpoints]


def load_activities(
    shared: Path,
    touchpoints: dict[str, Touchpoint],
    rows: dict[str, Row],
    stores_of: dict[str, str | None],
    knowledge: Knowledge,
    parties: set[str] | None = None,
) -> Activities:
    """Parse ``<shared>/activities/*.yaml`` and derive each one.

    ``touchpoints`` and ``rows`` are keyed by full id (``unit:id``);
    ``stores_of`` maps a data full id to its store full id. ``parties``
    (party ids) validates ``recipients``/``controller``/``processor`` when
    given.
    """
    result = Activities()
    folder = shared / ACTIVITIES_DIR
    if not folder.is_dir():
        return result
    for path in sorted(folder.glob("*.yaml")):
        spec = _load(path, result.diagnostics)
        if spec is None:
            continue
        activity = Activity(path.stem, spec, path)
        for ref in spec.touchpoints:
            tp = touchpoints.get(ref)
            if tp is None:
                result.diagnostics.append(
                    Diagnostic(
                        Severity.ERROR,
                        "activity-unknown-touchpoint",
                        f"{path.name}: no touchpoint {ref!r} "
                        "(`touchpoints list` shows the ids)",
                        "shared",
                        path,
                    )
                )
                continue
            activity.touchpoints.append(tp)
        if parties is not None:
            _check_parties(spec, parties, path, result.diagnostics)
        activity.derived = derive(activity.touchpoints, rows, stores_of, knowledge)
        result.items[path.stem] = activity
    return result


def _check_parties(
    spec: ActivityFile, parties: set[str], path: Path, diagnostics: list[Diagnostic]
) -> None:
    named = [(role, getattr(spec, role)) for role in ("controller", "processor")]
    named += [("recipient", value) for value in spec.recipients]
    diagnostics.extend(
        Diagnostic(
            Severity.ERROR,
            "party-unknown",
            f"{path.name}: {role} {value!r} is not in parties/",
            "shared",
            path,
        )
        for role, value in named
        if isinstance(value, str) and value not in parties
    )


def derive(
    touchpoints: list[Touchpoint],
    rows: dict[str, Row],
    stores_of: dict[str, str | None],
    knowledge: Knowledge,
) -> Derived:
    """Union of the touchpoints' data, then the register-level aggregates."""
    refs: set[str] = set()
    recipients: dict[str, set[str]] = {}
    for tp in touchpoints:
        refs.update(tp.data or ())
        for export in tp.exporting:
            recipients.setdefault(export.party, set()).update(export.data)
            refs.update(export.data)
    items = [rows[r] for r in sorted(refs) if r in rows]
    pii = [r.full_id for r in items if r.pii]
    categories = sorted(
        {c for r in items if r.pii and r.category for c in r.category.split("+")}
    )
    stores = sorted({s for r in items if (s := stores_of.get(r.full_id))})
    levels = [r.sensitivity for r in items if r.sensitivity in knowledge.sensitivity]
    level = (
        max(levels, key=lambda lv: knowledge.sensitivity[lv].rank) if levels else None
    )
    dpias = [r.dpia for r in items if r.dpia is not None]
    dpia = max(dpias, key=lambda d: d.rank) if dpias else None
    return Derived(
        data=[r.full_id for r in items],
        pii_data=pii,
        categories=categories,
        stores=stores,
        units=sorted({tp.unit for tp in touchpoints}),
        max_sensitivity=level,
        dpia=dpia,
        recipients={k: sorted(v) for k, v in sorted(recipients.items())},
    )


def _load(path: Path, diagnostics: list[Diagnostic]) -> ActivityFile | None:
    try:
        raw = load_yaml(path)
    except (OSError, yaml.YAMLError) as exc:
        diagnostics.append(
            Diagnostic(
                Severity.ERROR, "yaml-error", f"{path.name}: {exc}", "shared", path
            )
        )
        return None
    if not isinstance(raw, dict):
        diagnostics.append(
            Diagnostic(
                Severity.ERROR,
                "schema-error",
                f"{path.name}: expected a mapping",
                "shared",
                path,
            )
        )
        return None
    try:
        spec = ActivityFile.model_validate(raw)
    except ValidationError as exc:
        diagnostics.extend(
            Diagnostic(
                Severity.ERROR,
                "schema-error",
                f"{path.name}: {loc}: {msg}",
                "shared",
                path,
            )
            for loc, msg in format_errors(exc)
        )
        return None
    diagnostics.extend(
        Diagnostic(
            Severity.WARNING,
            "todo",
            f"{path.name}: {dotted} is still !todo",
            "shared",
            path,
        )
        for dotted in iter_todo_paths(spec)
    )
    return spec


def write_activity(
    shared: Path,
    slug: str,
    *,
    name: str | None,
    purpose: str | None,
    legal_basis: str | None,
    touchpoints: list[str],
    data_subjects: list[str] | None = None,
    recipients: list[str] | None = None,
    retention: str | None = None,
) -> Path | None:
    """Write ``activities/<slug>.yaml``; ``None`` when it already exists."""
    from model_wtf.compliance.yaml_io import todo_text

    path = shared / ACTIVITIES_DIR / f"{slug}.yaml"
    if path.exists():
        return None

    def scalar(value: str | None) -> str:
        if not value:
            return todo_text()
        return yaml.safe_dump(value, width=10**6).strip().removesuffix("\n...")

    lines = [
        f"name: {scalar(name)}",
        f"purpose: {scalar(purpose)}",
        f"legal_basis: {legal_basis or todo_text()}",
    ]
    if data_subjects:
        lines.append("data_subjects: [" + ", ".join(data_subjects) + "]")
    else:
        lines.append(f"data_subjects: {todo_text()}")
    lines.append("touchpoints:" if touchpoints else "touchpoints: []")
    lines.extend(f"  - {ref}" for ref in touchpoints)
    if recipients:
        lines.append("recipients: [" + ", ".join(recipients) + "]")
    lines.append(f"retention: {scalar(retention)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def add_touchpoints(path: Path, refs: list[str]) -> list[str]:
    """Append ``refs`` to an activity file's ``touchpoints`` list; return added.

    Edits the YAML textually so hand formatting and comments survive.
    """
    text = path.read_text(encoding="utf-8")
    raw = load_yaml(path) or {}
    current = list(raw.get("touchpoints") or [])
    added = [r for r in refs if r not in current]
    if not added:
        return []
    if "touchpoints: []" in text:
        text = text.replace(
            "touchpoints: []", "touchpoints:\n" + "\n".join(f"  - {r}" for r in added)
        )
    else:
        lines = text.splitlines()
        index = next(
            i for i, line in enumerate(lines) if line.startswith("touchpoints:")
        )
        end = index + 1
        while end < len(lines) and lines[end].startswith("  - "):
            end += 1
        lines[end:end] = [f"  - {r}" for r in added]
        text = "\n".join(lines) + "\n"
    path.write_text(text, encoding="utf-8")
    return added
