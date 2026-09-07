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
from typing import TYPE_CHECKING, Any, Literal

import yaml
from pydantic import Field, ValidationError, model_validator

from model_wtf.compliance.declarations import format_errors
from model_wtf.compliance.report import Diagnostic, Severity, marker_diagnostics
from model_wtf.compliance.schemas import NonEmpty, Slug, StrictModel
from model_wtf.compliance.yaml_io import Marker, Todo, load_yaml, marker_text, todo_text

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
    NO_PII = "no_pii"
    """Not an Art. 6 basis: a claim that the activity handles no personal
    item at all. Verified at every check (``no-pii-violated`` otherwise)."""


class Consent(StrictModel):
    """How a consent-based activity proves and scopes its consent."""

    record: str | Marker = Field(
        description="Full ref of the stored proof, created with "
        "`create: {consent_for: <this activity>}` by some touchpoint"
    )
    granularity: Literal["separate", "bundled"] = Field(
        default="separate",
        description="separate = asked on its own; bundled = tied to other "
        "purposes (Art. 7(4) warning)",
    )


class ActivityFile(StrictModel):
    """``activities/<slug>.yaml``."""

    name: NonEmpty | Marker = Field(description="Short name of the activity")
    purpose: NonEmpty | Marker = Field(
        description="Why the data is processed, as the register states it"
    )
    legal_basis: LegalBasis | Marker = Field(
        description="Art. 6 basis: contract, consent, legal_obligation, "
        "legitimate_interests, vital_interests or public_task; no_pii when "
        "the activity handles no personal item"
    )
    basis_note: NonEmpty | None = Field(
        default=None,
        description="When two bases compete: the candidates and the argument",
    )
    consent: Consent | None = Field(
        default=None, description="Required when legal_basis is consent"
    )
    interest: NonEmpty | Marker | None = Field(
        default=None,
        description="legitimate_interests: the balancing test (Art. 6(1)(f))",
    )
    dpia_reference: NonEmpty | Marker | None = Field(
        default=None,
        description="Where the DPIA lives, when the derived trigger fires (Art. 35)",
    )
    touchpoints: list[str] = Field(default_factory=list)
    data_subjects: list[NonEmpty] | Marker = Field(
        default_factory=list,
        description="Whose data: customers, staff, prospects, ...",
    )
    recipients: list[Slug] = Field(default_factory=list)
    retention: NonEmpty | Marker | None = Field(
        default=None,
        description="How long the data is kept and what starts the clock",
    )
    controller: Slug | Marker | None = Field(
        default=None, description="Party id, when not the app's controller"
    )
    processor: Slug | Marker | None = Field(
        default=None, description="Party id, when not the app's processor"
    )
    description: NonEmpty | None = None

    @model_validator(mode="after")
    def _basis_extras(self) -> ActivityFile:
        basis = self.legal_basis
        if basis is LegalBasis.CONSENT and self.consent is None:
            # Not an error: the proof is what KFF-208 checks for. A missing
            # block reads as ``consent.record: !todo``.
            self.consent = Consent(record=Todo())
        if basis is LegalBasis.LEGITIMATE_INTERESTS and self.interest is None:
            self.interest = Todo()
        return self


def list_dict() -> dict[str, list[str]]:
    """Default factory (a plain ``dict`` annotated for mypy)."""
    return {}


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
    """Party id → data items transferred to it by the touchpoints (derived,
    on top of the declared ``recipients`` list)."""
    ops: dict[str, list[str]] = field(default_factory=list_dict)
    """Full ref → union of the op verbs its touchpoints declare (``create``,
    ``erase``...). The rights derivation works from this."""


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
            key: None if isinstance(value, Marker) else value
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
                "ops": self.derived.ops,
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
    ops: dict[str, set[str]] = {}
    for tp in touchpoints:
        refs.update(tp.data or ())
        for ref in tp.data or ():
            ops.setdefault(ref, set()).update(o.op.value for o in tp.ops_of(ref))
        for export in tp.transfers:
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
        ops={k: sorted(v) for k, v in sorted(ops.items())},
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
    diagnostics.extend(marker_diagnostics(spec, path, "shared"))
    return spec


def write_activity(
    shared: Path,
    slug: str,
    *,
    name: str | None,
    purpose: str | Marker | None,
    legal_basis: str | Marker | None,
    touchpoints: list[str],
    data_subjects: list[str] | None = None,
    recipients: list[str] | None = None,
    retention: str | None = None,
    basis_note: str | None = None,
    consent_record: str | Marker | None = None,
    interest: str | Marker | None = None,
) -> Path | None:
    """Write ``activities/<slug>.yaml``; ``None`` when it already exists.

    A :class:`Marker` value is written as its tag (``!todo`` / ``!missing
    "note"``); ``None`` on a required field becomes ``!todo``. ``retention``
    is only written when given: the policy lives in ``retention_purge`` ops.
    """
    path = shared / ACTIVITIES_DIR / f"{slug}.yaml"
    if path.exists():
        return None

    def scalar(value: str | Marker | None) -> str:
        if value is None or value == "":
            return todo_text()
        if isinstance(value, Marker):
            return marker_text(value)
        return yaml.safe_dump(value, width=10**6).strip().removesuffix("\n...")

    lines = [
        f"name: {scalar(name)}",
        f"purpose: {scalar(purpose)}",
        f"legal_basis: {scalar(legal_basis)}",
    ]
    optional: list[tuple[bool, str]] = [
        (bool(basis_note), f"basis_note: {scalar(basis_note)}"),
        (
            legal_basis == LegalBasis.CONSENT or consent_record is not None,
            f"consent:\n  record: {scalar(consent_record)}",
        ),
        (
            legal_basis == LegalBasis.LEGITIMATE_INTERESTS or interest is not None,
            f"interest: {scalar(interest)}",
        ),
    ]
    lines.extend(text for wanted, text in optional if wanted)
    subjects = "[" + ", ".join(data_subjects) + "]" if data_subjects else todo_text()
    lines.append(f"data_subjects: {subjects}")
    lines.append("touchpoints:" if touchpoints else "touchpoints: []")
    lines.extend(f"  - {ref}" for ref in touchpoints)
    if recipients:
        lines.append("recipients: [" + ", ".join(recipients) + "]")
    if retention:
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
