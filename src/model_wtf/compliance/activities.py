"""Activities: GDPR processing activities, the Art. 30 register's rows.

An activity groups **touchpoints** (front routes, API endpoints, tasks,
admin screens) under one *purpose* with one legal basis. It is the only
object here with real legal fields; everything else about it is **derived**
from the touchpoints it lists: the data items they handle, hence the
categories, the stores, the maximum sensitivity and the DPIA trigger, and
the units involved.

Activities are rows of the ``activities`` table (they span units); read as
a mapping one looks like::

    name: Order fulfilment
    purpose: Take, pay and deliver restaurant orders
    legal_basis: contract
    data_subjects: [customers, restaurant staff]
    touchpoints: [front:/checkout, api:checkout, api:task:orders.send_receipt]
    recipients: [stripe]          # party ids; optional
    retention: 10 years (accounting)
    controller: fah               # defaults to the app's; processor likewise

Any legal field may be ``!todo``. "Process" is not used anywhere here: pytm
reserves it for a running component.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Literal

from pydantic import Field, ValidationError, model_validator
from sqlalchemy import select

from model_wtf.compliance.db import get_db
from model_wtf.compliance.declarations import format_errors
from model_wtf.compliance.report import Diagnostic, Severity, marker_diagnostics
from model_wtf.compliance.schemas import NonEmpty, Slug, StrictModel
from model_wtf.compliance.tables import (
    ActivityRecipientRow,
    ActivityRow,
    ActivityTouchpointRow,
)
from model_wtf.compliance.yaml_io import TODO, Marker, Todo

if TYPE_CHECKING:
    from model_wtf.compliance.data import Row
    from model_wtf.compliance.knowledge import Dpia, Knowledge
    from model_wtf.compliance.touchpoints import Touchpoint


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
    """One activity, as a mapping."""

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


def activity_label(slug: str) -> str:
    """How an activity is named in diagnostics and subjects."""
    return f"activities/{slug}"


@dataclass
class Activity:
    """One activity with its derivation."""

    slug: str
    spec: ActivityFile
    derived: Derived = field(default_factory=Derived)
    touchpoints: list[Touchpoint] = field(default_factory=list)
    """Resolved touchpoints (unknown references are reported, not kept)."""

    @property
    def label(self) -> str:
        """``activities/<slug>``."""
        return activity_label(self.slug)

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


def _activity_raw(row: ActivityRow) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "name": row.name,
        "purpose": row.purpose,
        "legal_basis": row.legal_basis,
        "touchpoints": [f"{t.unit}:{t.touchpoint_id}" for t in row.touchpoints],
        "data_subjects": row.data_subjects,
        "recipients": [r.party_id for r in row.recipients],
    }
    if row.consent_record is not None or row.consent_granularity is not None:
        consent: dict[str, Any] = {
            "record": row.consent_record if row.consent_record is not None else TODO
        }
        if row.consent_granularity is not None:
            consent["granularity"] = row.consent_granularity
        raw["consent"] = consent
    for key in (
        "basis_note",
        "interest",
        "dpia_reference",
        "retention",
        "controller",
        "processor",
        "description",
    ):
        value = getattr(row, key)
        if value is not None:
            raw[key] = value
    return raw


def declared_activities() -> dict[str, dict[str, Any]]:
    """Raw activity mappings by slug."""
    with get_db() as db:
        rows = db.scalars(select(ActivityRow).order_by(ActivityRow.slug)).all()
        return {row.slug: _activity_raw(row) for row in rows}


def load_activities(
    touchpoints: dict[str, Touchpoint],
    rows: dict[str, Row],
    stores_of: dict[str, str | None],
    knowledge: Knowledge,
    parties: set[str] | None = None,
) -> Activities:
    """Read the ``activities`` table and derive each one.

    ``touchpoints`` and ``rows`` are keyed by full id (``unit:id``);
    ``stores_of`` maps a data full id to its store full id. ``parties``
    (party ids) validates ``recipients``/``controller``/``processor`` when
    given.
    """
    result = Activities()
    for slug, raw in declared_activities().items():
        label = activity_label(slug)
        spec = _validate(raw, label, result.diagnostics)
        if spec is None:
            continue
        activity = Activity(slug, spec)
        for ref in spec.touchpoints:
            tp = touchpoints.get(ref)
            if tp is None:
                result.diagnostics.append(
                    Diagnostic(
                        Severity.ERROR,
                        "activity-unknown-touchpoint",
                        f"{label}: no touchpoint {ref!r} "
                        "(`touchpoints list` shows the ids)",
                        "shared",
                    )
                )
                continue
            activity.touchpoints.append(tp)
        if parties is not None:
            _check_parties(spec, parties, label, result.diagnostics)
        activity.derived = derive(activity.touchpoints, rows, stores_of, knowledge)
        result.items[slug] = activity
    return result


def _check_parties(
    spec: ActivityFile, parties: set[str], label: str, diagnostics: list[Diagnostic]
) -> None:
    named = [(role, getattr(spec, role)) for role in ("controller", "processor")]
    named += [("recipient", value) for value in spec.recipients]
    diagnostics.extend(
        Diagnostic(
            Severity.ERROR,
            "party-unknown",
            f"{label}: {role} {value!r} is not a declared party",
            "shared",
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


def _validate(
    raw: dict[str, Any], label: str, diagnostics: list[Diagnostic]
) -> ActivityFile | None:
    try:
        spec = ActivityFile.model_validate(raw)
    except ValidationError as exc:
        diagnostics.extend(
            Diagnostic(
                Severity.ERROR,
                "schema-error",
                f"{label}: {loc}: {msg}",
                "shared",
            )
            for loc, msg in format_errors(exc)
        )
        return None
    diagnostics.extend(marker_diagnostics(spec, label, "shared"))
    return spec


def write_activity(
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
) -> bool:
    """Create an activity; ``False`` when the slug already exists.

    A :class:`Marker` value is stored as such; ``None`` on a required field
    becomes ``!todo``. ``retention`` is only stored when given: the policy
    lives in ``retention_purge`` ops.
    """

    def human(value: str | Marker | None) -> str | Marker:
        return TODO if value is None or value == "" else value

    with get_db() as db:
        if db.get(ActivityRow, slug) is not None:
            return False
        row = ActivityRow(
            slug=slug,
            name=human(name),
            purpose=human(purpose),
            legal_basis=human(legal_basis),
            basis_note=basis_note or None,
            consent_record=(
                human(consent_record)
                if legal_basis == LegalBasis.CONSENT or consent_record is not None
                else None
            ),
            interest=(
                human(interest)
                if legal_basis == LegalBasis.LEGITIMATE_INTERESTS
                or interest is not None
                else None
            ),
            data_subjects=list(data_subjects) if data_subjects else TODO,
            retention=retention or None,
        )
        row.touchpoints = [
            ActivityTouchpointRow(
                slug=slug,
                unit=ref.split(":", 1)[0],
                touchpoint_id=ref.split(":", 1)[1],
                position=index,
            )
            for index, ref in enumerate(touchpoints)
        ]
        row.recipients = [
            ActivityRecipientRow(slug=slug, party_id=p) for p in recipients or []
        ]
        db.add(row)
    return True


ACTIVITY_FACTS: frozenset[str] = frozenset(
    {
        "name",
        "purpose",
        "legal_basis",
        "basis_note",
        "consent_record",
        "consent_granularity",
        "interest",
        "dpia_reference",
        "data_subjects",
        "retention",
        "controller",
        "processor",
        "description",
    }
)
"""Columns of an activity a human answers (the ``!todo`` questions)."""


def _apply_change(raw: dict[str, Any], key: str, value: Any) -> None:
    """Apply one column change to an activity's raw mapping (``consent_*``
    live under the ``consent`` block)."""
    if key in ("consent_record", "consent_granularity"):
        consent = dict(raw.get("consent") or {})
        sub = "record" if key == "consent_record" else "granularity"
        if value is None:
            consent.pop(sub, None)
        else:
            consent[sub] = value
        if consent:
            raw["consent"] = {"record": TODO, **consent}
        else:
            raw.pop("consent", None)
    elif value is None:
        raw.pop(key, None)
    else:
        raw[key] = value


def update_activity(slug: str, **changes: Any) -> None:
    """Set columns of an existing activity; ``recipients`` replaces the list.

    A ``None`` clears an optional column; a required one (``name``,
    ``purpose``, ``legal_basis``, ``data_subjects``) takes a :class:`Marker`
    instead. The result must still validate as an :class:`ActivityFile`; a
    ``ValueError`` names the problem. Raises ``KeyError`` when no such slug.
    """
    unknown = set(changes) - ACTIVITY_FACTS - {"recipients"}
    if unknown:
        msg = f"unknown activity fields: {', '.join(sorted(unknown))}"
        raise ValueError(msg)
    with get_db() as db:
        row = db.get(ActivityRow, slug)
        if row is None:
            raise KeyError(slug)
        raw = _activity_raw(row)
        for key, value in changes.items():
            _apply_change(raw, key, value)
        try:
            ActivityFile.model_validate(raw)
        except ValidationError as exc:
            problems = "; ".join(f"{loc}: {msg}" for loc, msg in format_errors(exc))
            raise ValueError(problems) from exc
        for key, value in changes.items():
            if key == "recipients":
                row.recipients = [
                    ActivityRecipientRow(slug=slug, party_id=p) for p in value
                ]
            else:
                setattr(row, key, value)


def add_touchpoints(slug: str, refs: list[str]) -> list[str]:
    """Append ``refs`` to an activity's touchpoint list; return the added ones."""
    with get_db() as db:
        row = db.get(ActivityRow, slug)
        if row is None:
            return []
        current = {f"{t.unit}:{t.touchpoint_id}" for t in row.touchpoints}
        added = [r for r in refs if r not in current and r not in added_seen(refs, r)]
        for offset, ref in enumerate(added):
            unit, _, tp_id = ref.partition(":")
            row.touchpoints.append(
                ActivityTouchpointRow(
                    slug=slug,
                    unit=unit,
                    touchpoint_id=tp_id,
                    position=len(row.touchpoints) + offset,
                )
            )
    return added


def added_seen(refs: list[str], ref: str) -> set[str]:
    """Refs listed before ``ref`` (so a duplicate in the input is added once)."""
    return set(refs[: refs.index(ref)])


def activities_of_touchpoint(unit_id: str, touchpoint_id: str) -> list[str]:
    """Slugs of the activities listing ``unit:touchpoint_id``."""
    with get_db() as db:
        return list(
            db.scalars(
                select(ActivityTouchpointRow.slug)
                .where(
                    ActivityTouchpointRow.unit == unit_id,
                    ActivityTouchpointRow.touchpoint_id == touchpoint_id,
                )
                .order_by(ActivityTouchpointRow.slug)
            ).all()
        )
