"""``compliance render --format registry``: the Art. 30 record as Markdown.

The registry is *derived*: activities x data objects x recipients from the
declarations, categories of personal data from the union of the data
objects' items, rights from lawful basis x identification. Nothing is
extracted from code here and nothing depends on the run (no timestamps,
no hashes), so the output is diffable and can be committed.

Templates are one Jinja file per declaration kind under
``templates/registry/`` so the later renderers (STRIDE, PDF/HTML) can
reuse the same blocks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from model_wtf.compliance.check import SHARED_FOLDER
from model_wtf.compliance.declarations.loader import (
    DeclarationSet,
    Kind,
    load_declarations,
)
from model_wtf.compliance.declarations.schemas import (
    Activity,
    Actor,
    Controller,
    DataObject,
    Identification,
    LawfulBasis,
    OpaqueField,
    Recipient,
    Rectification,
    Retention,
    ScalarField,
)
from model_wtf.compliance.discovery import load_units, select_manifest
from model_wtf.compliance.yamlio import filled, filled_list
from model_wtf.knowledge.loader import load_knowledge

if TYPE_CHECKING:
    from collections.abc import Iterable

    from model_wtf.knowledge.loader import Knowledge

TEMPLATES = Path(__file__).resolve().parent / "templates" / "registry"

YES = "yes"
NO = "no"
BLANK = "_(to be filled)_"


# ---------------------------------------------------------------------------
# View model
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RetentionRow:
    """One erasure time limit, with where it comes from."""

    source: str
    time_limit: str
    trigger: str
    expiry_action: str
    statutory_basis: str | None


@dataclass(frozen=True, slots=True)
class RightsRow:
    """Rights derived for one data object inside one activity."""

    data_object: str
    access: str
    rectification: str
    erasure: str
    restriction: str
    portability: str
    objection: str
    withdrawal: str


@dataclass(frozen=True, slots=True)
class ActivityView:
    """Everything an activity section prints."""

    id: str
    purpose: str
    lawful_basis: str
    dpia_reference: str | None
    subjects: list[str]
    items: list[str]
    recipients: list[str]
    data_objects: list[str]
    retention: list[RetentionRow]
    rights: list[RightsRow]


@dataclass(frozen=True, slots=True)
class RecipientView:
    """Recipient section."""

    id: str
    name: str
    kind: str
    dpa_reference: str | None
    third_country: str | None
    transfer_safeguards: str | None
    retention: list[RetentionRow]


@dataclass(frozen=True, slots=True)
class DataObjectView:
    """Data object section."""

    id: str
    name: str
    description: str
    subjects: list[str]
    items: list[str]
    identification: str
    rectification: str
    multi_subject: bool


@dataclass(frozen=True, slots=True)
class UnitView:
    """One unit's registry."""

    id: str
    controller: Controller | None
    security: str | None
    activities: list[ActivityView] = field(default_factory=list)
    recipients: list[RecipientView] = field(default_factory=list)
    data_objects: list[DataObjectView] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Derivation
# ---------------------------------------------------------------------------


def build_unit_view(unit_id: str, ds: DeclarationSet, knowledge: Knowledge) -> UnitView:
    """Derive the registry view of one unit from its declarations."""
    controller = ds.controller.model if ds.controller else None
    security = ds.unit.security.model if ds.unit.security else None
    data_objects = {
        d.id: d.model
        for d in ds.unit.get(Kind.DATA_OBJECT).values()
        if isinstance(d.model, DataObject) and d.model.personal_data
    }
    recipients = {
        r.id: r.model
        for r in ds.all(Kind.RECIPIENT).values()
        if isinstance(r.model, Recipient)
    }

    return UnitView(
        id=unit_id,
        controller=controller,
        security=filled(security.general_description) if security else None,
        activities=[
            _activity_view(
                declared.id,
                declared.model,
                declared.gen,
                ds,
                data_objects,
                recipients,
                knowledge,
            )
            for declared in sorted(
                ds.unit.get(Kind.ACTIVITY).values(), key=lambda d: d.id
            )
            if isinstance(declared.model, Activity)
        ],
        recipients=[
            RecipientView(
                id=rid,
                name=model.name,
                kind=model.kind.value,
                dpa_reference=filled(model.dpa_reference),
                third_country=model.third_country,
                transfer_safeguards=filled(model.transfer_safeguards),
                retention=_retention_rows(rid, model.retention),
            )
            for rid, model in sorted(recipients.items())
        ],
        data_objects=[
            DataObjectView(
                id=oid,
                name=model.name or oid,
                description=model.description,
                subjects=_actor_names(filled_list(model.subject_categories), ds),
                items=item_labels(_object_items(model), knowledge),
                identification=(
                    ident.value if (ident := filled(model.identification)) else BLANK
                ),
                rectification=(
                    rect.value if (rect := filled(model.rectification)) else BLANK
                ),
                multi_subject=model.multi_subject,
            )
            for oid, model in sorted(data_objects.items())
        ],
    )


def _activity_view(
    activity_id: str,
    model: Activity,
    gen: object,
    ds: DeclarationSet,
    data_objects: dict[str, DataObject],
    recipients: dict[str, Recipient],
    knowledge: Knowledge,
) -> ActivityView:
    linked_ids = sorted(_gen_data_objects(gen))
    linked = [(oid, data_objects[oid]) for oid in linked_ids if oid in data_objects]
    items: set[str] = set()
    retention: list[RetentionRow] = []
    for oid, obj in linked:
        items |= _object_items(obj)
        retention.extend(_retention_rows(f"data object {oid}", obj.retention))
    for rid in sorted(model.recipients):
        if rid in recipients:
            retention.extend(
                _retention_rows(f"recipient {rid}", recipients[rid].retention)
            )
    basis = filled(model.lawful_basis)
    return ActivityView(
        id=activity_id,
        purpose=filled(model.purpose) or BLANK,
        lawful_basis=basis.value if basis else BLANK,
        dpia_reference=filled(model.dpia_reference),
        subjects=_actor_names(filled_list(model.data_subject_categories), ds),
        items=item_labels(items, knowledge),
        recipients=[
            _recipient_label(rid, recipients.get(rid))
            for rid in sorted(model.recipients)
        ],
        data_objects=linked_ids,
        retention=retention,
        rights=[rights_row(oid, basis, obj) for oid, obj in linked] if basis else [],
    )


def _gen_data_objects(gen: object) -> Iterable[str]:
    extra = getattr(gen, "model_extra", None) or {}
    value = extra.get("data_objects")
    if isinstance(value, dict):
        return [str(k) for k in value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def _object_items(model: DataObject) -> set[str]:
    out: set[str] = set()
    for spec in model.fields.values():
        if isinstance(spec, ScalarField):
            out.add(spec.item)
        elif isinstance(spec, OpaqueField):
            out.update(c.item for c in spec.contents)
    return out


def item_labels(items: Iterable[str], knowledge: Knowledge) -> list[str]:
    """Human labels for vocabulary items, Art. 9 flagged, ``none`` dropped."""
    labels: list[str] = []
    for item in sorted(items):
        if item == "none":
            continue
        entry = knowledge.data_items.get(item)
        label = entry.name if entry else item
        if entry and entry.special_art9:
            label += " (Art. 9)"
        labels.append(label)
    return labels


def _actor_names(ids: Iterable[str], ds: DeclarationSet) -> list[str]:
    names: list[str] = []
    for actor_id in sorted(ids):
        declared = ds.resolve(Kind.ACTOR, actor_id)
        model = declared.model if declared else None
        names.append(model.name if isinstance(model, Actor) else actor_id)
    return names


def _recipient_label(rid: str, model: Recipient | None) -> str:
    if model is None:
        return rid
    label = f"{model.name} ({model.kind.value}"
    if model.third_country:
        label += f", {model.third_country}"
        if model.transfer_safeguards:
            label += f": {model.transfer_safeguards}"
    return label + ")"


def _retention_rows(source: str, retention: Iterable[Retention]) -> list[RetentionRow]:
    return [
        RetentionRow(
            source=source,
            time_limit=filled(r.time_limit) or BLANK,
            trigger=filled(r.trigger) or BLANK,
            expiry_action=r.expiry_action.value,
            statutory_basis=r.statutory_basis,
        )
        for r in retention
    ]


def rights_row(object_id: str, basis: LawfulBasis, obj: DataObject) -> RightsRow:
    """Apply the rights-derivation table: lawful basis x identification.

    ``identification: none`` means no rights machinery at all (Art. 11(2));
    the object must instead carry tight retention, which the gates check.
    """
    if filled(obj.identification) is Identification.NONE:
        none = "n/a (Art. 11(2))"
        return RightsRow(object_id, none, none, none, none, none, none, none)
    return RightsRow(
        data_object=object_id,
        access=YES,
        rectification=(
            "self-service"
            if obj.rectification is Rectification.SELF_SERVICE
            else "via DPO"
        ),
        erasure=(
            NO + " (Art. 17(3))"
            if basis in (LawfulBasis.LEGAL_OBLIGATION, LawfulBasis.PUBLIC_TASK)
            else YES
        ),
        restriction=YES,
        portability=YES if basis in (LawfulBasis.CONSENT, LawfulBasis.CONTRACT) else NO,
        objection=(
            YES
            if basis in (LawfulBasis.LEGITIMATE_INTEREST, LawfulBasis.PUBLIC_TASK)
            else NO
        ),
        withdrawal=YES if basis is LawfulBasis.CONSENT else NO,
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def environment() -> Environment:
    """The Jinja environment shared by the Markdown renderers."""
    return Environment(  # noqa: S701 - Markdown, not HTML
        loader=FileSystemLoader(str(TEMPLATES)),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=False,
    )


def render_registry(root: Path) -> str:
    """The whole repository's Art. 30 record as Markdown.

    Raises
    ------
    DeclarationError
        When the manifest is missing or malformed.
    """
    root = root.resolve()
    knowledge = load_knowledge()
    units, _ = load_units(select_manifest(root), root, strict=False)
    shared = root / SHARED_FOLDER
    views: list[UnitView] = []
    for unit in units:
        ds, _ = load_declarations(unit.folder, shared, unit.id)
        views.append(build_unit_view(unit.id, ds, knowledge))
    if not views:
        ds, _ = load_declarations(shared, shared, "shared")
        views.append(build_unit_view("shared", ds, knowledge))
    text = environment().get_template("registry.md.j2").render(units=views)
    return _normalise(text)


def _normalise(text: str) -> str:
    """Collapse blank-line runs and end with exactly one newline."""
    lines: list[str] = []
    for line in text.replace("\r\n", "\n").split("\n"):
        stripped = line.rstrip()
        if stripped == "" and lines and lines[-1] == "":
            continue
        lines.append(stripped)
    while lines and lines[-1] == "":
        lines.pop()
    while lines and lines[0] == "":
        lines.pop(0)
    return "\n".join(lines) + "\n"
