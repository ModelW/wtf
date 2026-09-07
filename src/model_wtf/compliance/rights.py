"""Rights coverage: what the GDPR owes each personal item, and whether the code does it.

Three sources of truth meet here, and nothing about rights is written
anywhere else:

* **touchpoints** state what the code does to an item (:mod:`ops`);
* **data items** state what is true of the data regardless of code — an
  exemption (``rights: {erase: {exempt: legal_obligation, note: ...}}``) or an
  agent's observation that a right is unmet (``rights: {erase: !missing
  "..."}``);
* **activities** carry the purpose and the legal basis (plus, for consent,
  the stored proof).

Everything else is derived, per personal item, in every activity that
handles it: the derivation walks the table in :data:`CHECKS`, and each
unmet right becomes a ``Missing`` diagnostic tagged with its origin —
``derived`` (the tool, from ops and exemptions), ``claimed`` (an agent that
read the code) or ``declared`` (a human's ``!missing``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, model_validator

from model_wtf.compliance.ops import Op
from model_wtf.compliance.report import Diagnostic, Severity
from model_wtf.compliance.yaml_io import Marker, Missing

if TYPE_CHECKING:
    from pathlib import Path

    from model_wtf.compliance.activities import Activity
    from model_wtf.compliance.data import Row
    from model_wtf.compliance.ops import OpSpec
    from model_wtf.compliance.touchpoints import Touchpoint
    from model_wtf.compliance.workspace import Workspace

__all__ = [
    "AGENT_PREFIX",
    "EXEMPT_NOTE_REQUIRED",
    "Exemption",
    "Ground",
    "Right",
    "RightStatus",
    "RightsSpec",
    "check_rights",
    "rights_of",
    "set_right",
]


class Right(StrEnum):
    """What can be exempted or found missing on a data item."""

    ACCESS = "access"
    RECTIFY = "rectify"
    ERASE = "erase"
    RETENTION = "retention"
    PORTABILITY = "portability"
    OBJECT = "object"
    CONSENT = "consent"
    TRANSFER = "transfer"


class Ground(StrEnum):
    """Why a right does not apply to an item; each tied to the text."""

    LEGAL_OBLIGATION = "legal_obligation"
    """Art. 17(3)(b): kept because the law says so; note states the period."""

    CONTRACT_ACTIVE = "contract_active"
    """Art. 17(1)(a): the purpose is not fulfilled yet (the open account);
    an ``erase`` with ``on: <event>`` is still required somewhere."""

    NOT_PROVIDED_BY_SUBJECT = "not_provided_by_subject"
    """Art. 20 scope: portability only covers data the subject provided."""

    DERIVED = "derived"
    """Computed from other data: nothing to rectify or port on its own."""

    STAFF_ONLY = "staff_only"
    """Served by staff on request; verified against a ``by: staff`` op."""

    MANUAL = "manual"
    """Handled outside the code; always surfaced for review."""

    PUBLIC_INTEREST = "public_interest"
    RESEARCH = "research"
    LEGAL_CLAIMS = "legal_claims"
    """Art. 17(3)(c-e)."""


EXEMPT_NOTE_REQUIRED = frozenset(
    {
        Ground.LEGAL_OBLIGATION,
        Ground.MANUAL,
        Ground.PUBLIC_INTEREST,
        Ground.RESEARCH,
        Ground.LEGAL_CLAIMS,
    }
)
"""Grounds that mean nothing without the note saying which law / which process."""

_GROUND_RIGHTS: dict[Ground, frozenset[Right]] = {
    Ground.NOT_PROVIDED_BY_SUBJECT: frozenset({Right.PORTABILITY}),
    Ground.DERIVED: frozenset({Right.RECTIFY, Right.PORTABILITY}),
}
"""Grounds that only make sense for some rights; the others apply to any."""

AGENT_PREFIX = "[agent]"
"""Note prefix an agent writes; ``check`` shows such findings as *claimed*."""


class Exemption(BaseModel):
    """``{exempt: <ground>, note?}`` on one right of one item."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    exempt: Ground
    note: str | None = None

    @model_validator(mode="after")
    def _note_when_needed(self) -> Exemption:
        if self.exempt in EXEMPT_NOTE_REQUIRED and not (self.note or "").strip():
            msg = f"exempt: {self.exempt.value} needs a note (which law / process)"
            raise ValueError(msg)
        return self


RightValue = Exemption | Marker
"""An exemption, or ``!missing`` (unmet, observed) / ``!todo`` (not looked at)."""


class RightsSpec(BaseModel):
    """The ``rights:`` block of a data file, one entry per right."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    access: RightValue | None = None
    rectify: RightValue | None = None
    erase: RightValue | None = None
    retention: RightValue | None = None
    portability: RightValue | None = None
    object: RightValue | None = None
    consent: RightValue | None = None
    transfer: RightValue | None = None

    @model_validator(mode="after")
    def _grounds_fit_rights(self) -> RightsSpec:
        for right in Right:
            value = getattr(self, right.value)
            if not isinstance(value, Exemption):
                continue
            allowed = _GROUND_RIGHTS.get(value.exempt)
            if allowed is not None and right not in allowed:
                names = ", ".join(sorted(r.value for r in allowed))
                msg = f"{right.value}: exempt {value.exempt.value} only for {names}"
                raise ValueError(msg)
        return self

    def get(self, right: Right) -> RightValue | None:
        """The entry for ``right``, if any."""
        value: RightValue | None = getattr(self, right.value)
        return value

    def is_empty(self) -> bool:
        """Whether no right is declared."""
        return all(getattr(self, r.value) is None for r in Right)


class RightStatus(StrEnum):
    """Outcome of one right for one item."""

    SATISFIED = "satisfied"
    EXEMPT = "exempt"
    MISSING = "missing"
    NOT_APPLICABLE = "n/a"


Origin = Literal["derived", "claimed", "declared"]


@dataclass(frozen=True)
class Finding:
    """One right on one item, with what decided it."""

    ref: str
    right: Right
    status: RightStatus
    article: str
    detail: str
    """``satisfied by api:signup`` / ``exempt: legal_obligation`` / why missing."""
    origin: Origin | None = None
    note: str | None = None

    def code(self) -> str:
        """Diagnostic code, ``<right>-missing`` style."""
        names = {
            Right.ACCESS: "access-missing",
            Right.RECTIFY: "rectification-missing",
            Right.ERASE: "erasure-missing",
            Right.RETENTION: "retention-missing",
            Right.PORTABILITY: "portability-missing",
            Right.OBJECT: "objection-missing",
            Right.CONSENT: "consent-missing",
            Right.TRANSFER: "transfer-safeguard-missing",
        }
        return names[self.right]


@dataclass
class ItemRights:
    """Every right's status for one personal item."""

    ref: str
    findings: list[Finding] = field(default_factory=list)

    def missing(self) -> list[Finding]:
        """The unmet ones."""
        return [f for f in self.findings if f.status is RightStatus.MISSING]


def rights_of(ref: str, ws: Workspace) -> ItemRights:
    """Compute the status of every right for one item, across its activities."""
    return _Derivation(ws).item(ref)


def check_rights(ws: Workspace) -> tuple[list[Diagnostic], dict[str, ItemRights]]:
    """Every rights finding of the workspace as diagnostics, plus the per-item detail.

    Diagnostics: one ``Missing`` per unmet right per item (origin in the
    message), one ``manual-exemption`` Review line per item resting on a
    ``manual`` ground, plus the activity-level checks (consent proof and
    withdrawal, objection, DPIA, ``no_pii`` violated, third-country
    transfers).
    """
    return _Derivation(ws).run()


# ---------------------------------------------------------------------------
# derivation
# ---------------------------------------------------------------------------

_ARTICLE = {
    Right.ACCESS: "Art. 15",
    Right.RECTIFY: "Art. 16",
    Right.ERASE: "Art. 17",
    Right.RETENTION: "Art. 5(1)(e)",
    Right.PORTABILITY: "Art. 20",
    Right.OBJECT: "Art. 21",
    Right.CONSENT: "Art. 7",
    Right.TRANSFER: "Ch. V",
}
_OP_FOR = {
    Right.ACCESS: Op.ACCESS,
    Right.RECTIFY: Op.RECTIFY,
    Right.ERASE: Op.ERASE,
    Right.PORTABILITY: Op.PORTABILITY,
}


class _Derivation:
    def __init__(self, ws: Workspace) -> None:
        self.ws = ws
        self.rows = ws.rows
        self.adequacy = ws.knowledge.adequacy
        # ref -> [(touchpoint, op)] for every op declared on it.
        self.ops: dict[str, list[tuple[Touchpoint, OpSpec]]] = {}
        for tp in ws.all_touchpoints.values():
            for ref in tp.data or ():
                for op in tp.ops_of(ref):
                    self.ops.setdefault(ref, []).append((tp, op))

    # -- entry points -------------------------------------------------------

    def run(self) -> tuple[list[Diagnostic], dict[str, ItemRights]]:
        diagnostics: list[Diagnostic] = []
        items: dict[str, ItemRights] = {}
        for activity in self.ws.activities.items.values():
            diagnostics.extend(self._activity_checks(activity))
            for ref in activity.derived.pii_data:
                if ref in items or ref not in self.rows:
                    continue
                items[ref] = self.item(ref)
        for ref, item in sorted(items.items()):
            row = self.rows[ref]
            spec = row.rights
            if spec is not None:
                for right in Right:
                    value = spec.get(right)
                    if isinstance(value, Exemption) and value.exempt is Ground.MANUAL:
                        diagnostics.append(
                            Diagnostic(
                                Severity.WARNING,
                                "manual-exemption",
                                f"{ref}: {right.value} handled outside the code "
                                f"({value.note})",
                                row.unit,
                                self._path(row),
                                subject=f"{ref}#{right.value}",
                                hint="confirm the process still exists",
                            )
                        )
            for finding in item.missing():
                diagnostics.append(self._diagnostic(row, finding))
        return diagnostics, items

    def item(self, ref: str) -> ItemRights:
        row = self.rows[ref]
        activities = self.ws.activities.holding(ref)
        bases = {
            a.spec.legal_basis.value
            for a in activities
            if not isinstance(a.spec.legal_basis, Marker)
        }
        out = ItemRights(ref)
        if not row.pii or not activities or bases == {"no_pii"}:
            return out
        for right in (Right.ACCESS, Right.RECTIFY, Right.ERASE, Right.RETENTION):
            out.findings.append(self._simple(row, right, bases))
        if _portability_applies(bases, self.ops.get(ref, [])):
            out.findings.append(self._simple(row, Right.PORTABILITY, bases))
        transfer = self._transfer(row)
        if transfer is not None:
            out.findings.append(transfer)
        return out

    # -- one right ----------------------------------------------------------

    def _simple(self, row: Row, right: Right, bases: set[str]) -> Finding:
        ref = row.full_id
        article = _ARTICLE[right]
        # 1. what the item says about itself
        declared = row.rights.get(right) if row.rights is not None else None
        if isinstance(declared, Missing):
            origin: Origin = "claimed" if _is_agent(declared.note) else "declared"
            return Finding(
                ref,
                right,
                RightStatus.MISSING,
                article,
                "stated unmet",
                origin,
                declared.note,
            )
        if isinstance(declared, Exemption):
            return self._exempt(row, right, declared, article)
        # 2. exemptions by construction
        if right is Right.ERASE and "legal_obligation" in bases:
            return Finding(
                ref,
                right,
                RightStatus.EXEMPT,
                article,
                "activity rests on a legal obligation",
            )
        if right is Right.RETENTION and "legal_obligation" in bases:
            return Finding(
                ref,
                right,
                RightStatus.EXEMPT,
                article,
                "activity rests on a legal obligation",
            )
        # 3. what the code does
        return self._from_ops(row, right, article)

    def _exempt(self, row: Row, right: Right, ex: Exemption, article: str) -> Finding:
        ref = row.full_id
        detail = f"exempt: {ex.exempt.value}" + (f" ({ex.note})" if ex.note else "")
        if ex.exempt is Ground.STAFF_ONLY:
            op = _OP_FOR.get(right)
            staff = [
                tp
                for tp, o in self.ops.get(ref, [])
                if op is not None and o.op is op and o.payload().get("by") == "staff"
            ]
            if not staff:
                return Finding(
                    ref,
                    right,
                    RightStatus.MISSING,
                    article,
                    f"exempt staff_only but no touchpoint does {right.value} by staff",
                    "derived",
                )
            detail += f", served by {', '.join(t.full_id for t in staff)}"
        if ex.exempt is Ground.CONTRACT_ACTIVE and right is Right.ERASE:
            triggered = [
                tp
                for tp, o in self.ops.get(ref, [])
                if o.op is Op.ERASE and o.payload().get("on")
            ]
            if not triggered:
                return Finding(
                    ref,
                    right,
                    RightStatus.MISSING,
                    article,
                    "exempt contract_active but no `erase` with `on: <event>` "
                    "closes the contract",
                    "derived",
                )
            detail += f", erased on event by {', '.join(t.full_id for t in triggered)}"
        return Finding(ref, right, RightStatus.EXEMPT, article, detail)

    def _from_ops(self, row: Row, right: Right, article: str) -> Finding:
        ref = row.full_id
        declared = self.ops.get(ref, [])
        if right is Right.RETENTION:
            purges = [tp for tp, o in declared if o.op is Op.RETENTION_PURGE]
            events = [
                tp for tp, o in declared if o.op is Op.ERASE and o.payload().get("on")
            ]
            if purges or events:
                by = ", ".join(t.full_id for t in purges + events)
                return Finding(
                    ref, right, RightStatus.SATISFIED, article, f"satisfied by {by}"
                )
            return Finding(
                ref,
                right,
                RightStatus.MISSING,
                article,
                "no retention_purge and no event-driven erase",
                "derived",
            )
        op = _OP_FOR[right]
        hits = [(tp, o) for tp, o in declared if o.op is op]
        if right is Right.ERASE:
            anonymised = [
                tp for tp, o in hits if o.payload().get("mode") == "anonymise"
            ]
            grounds = row.rights.get(Right.ERASE) if row.rights is not None else None
            if (
                anonymised
                and len(anonymised) == len(hits)
                and not isinstance(grounds, Exemption)
            ):
                return Finding(
                    ref,
                    right,
                    RightStatus.MISSING,
                    article,
                    "anonymisation without a ground to keep the row "
                    "(add rights.erase exempt legal_obligation|legal_claims)",
                    "derived",
                )
        if hits:
            by = ", ".join(tp.full_id for tp, _ in hits)
            return Finding(
                ref, right, RightStatus.SATISFIED, article, f"satisfied by {by}"
            )
        return Finding(
            ref,
            right,
            RightStatus.MISSING,
            article,
            f"no {op.value} op reaches it",
            "derived",
        )

    def _transfer(self, row: Row) -> Finding | None:
        ref = row.full_id
        parties = self.ws.parties
        sent_to = sorted(
            {
                t.party
                for tp in self.ws.all_touchpoints.values()
                for t in tp.transfers
                if ref in t.data
            }
        )
        if not sent_to:
            return None
        declared = row.rights.get(Right.TRANSFER) if row.rights is not None else None
        if isinstance(declared, Missing):
            origin: Origin = "claimed" if _is_agent(declared.note) else "declared"
            return Finding(
                ref,
                Right.TRANSFER,
                RightStatus.MISSING,
                "Ch. V",
                "stated unmet",
                origin,
                declared.note,
            )
        unsafe: list[str] = []
        for slug in sent_to:
            party = parties.get(slug)
            if party is None:
                continue
            country = party.country if isinstance(party.country, str) else None
            if country is None or country.upper() in self.adequacy:
                continue
            safeguard = getattr(party, "safeguard", None)
            if safeguard is None or (
                safeguard == "dpf" and not getattr(party, "dpf_certified", False)
            ):
                unsafe.append(f"{slug} ({country})")
        if unsafe:
            return Finding(
                ref,
                Right.TRANSFER,
                RightStatus.MISSING,
                "Ch. V",
                "third-country transfer without safeguard: "
                + ", ".join(unsafe)
                + " (set safeguard: sccs|bcr|dpf|derogation on the party)",
                "derived",
            )
        return Finding(
            ref,
            Right.TRANSFER,
            RightStatus.SATISFIED,
            "Ch. V",
            f"sent to {', '.join(sent_to)}",
        )

    # -- activity level -----------------------------------------------------

    def _activity_checks(self, activity: Activity) -> list[Diagnostic]:
        spec = activity.spec
        basis = spec.legal_basis if not isinstance(spec.legal_basis, Marker) else None
        if basis is None:
            return self._dpia_check(activity)
        out: list[Diagnostic] = []
        if basis.value == "no_pii" and activity.derived.pii_data:
            shown = ", ".join(activity.derived.pii_data[:3])
            more = len(activity.derived.pii_data) - 3
            if more > 0:
                shown += f", … (+{more})"
            out.append(
                self._activity_diag(
                    activity,
                    "no-pii-violated",
                    f"legal_basis no_pii but personal items are handled: {shown}",
                    hint="give the activity a real legal basis, or fix the pii flags",
                )
            )
        if basis.value == "consent":
            out.extend(self._consent_checks(activity))
        if basis.value == "legitimate_interests":
            out.extend(self._objection_check(activity))
        out.extend(self._dpia_check(activity))
        return out

    def _consent_checks(self, activity: Activity) -> list[Diagnostic]:
        """Art. 7: a stored proof created for this activity, and a way out."""
        out: list[Diagnostic] = []
        consent = activity.spec.consent
        slug = activity.slug
        if consent is None or isinstance(consent.record, Marker):
            out.append(
                self._activity_diag(
                    activity,
                    "consent-proof-missing",
                    "consent: no stored proof (`consent.record` names the item "
                    "carrying `create: {consent_for: <slug>}`)",
                )
            )
        else:
            proofs = [
                tp
                for tp, o in self.ops.get(consent.record, [])
                if o.op is Op.CREATE and o.payload().get("consent_for") == slug
            ]
            if not proofs:
                out.append(
                    self._activity_diag(
                        activity,
                        "consent-proof-missing",
                        f"consent.record {consent.record} is created by no "
                        f"touchpoint with `consent_for: {slug}`",
                    )
                )
            if consent.granularity == "bundled":
                out.append(
                    self._activity_diag(
                        activity,
                        "consent-bundled",
                        "consent is bundled with other purposes (Art. 7(4): "
                        "freely given?)",
                        severity=Severity.INFO,
                    )
                )
        withdrawals = [
            tp
            for tp in self.ws.all_touchpoints.values()
            for ref in tp.data or ()
            for o in tp.ops_of(ref)
            if o.op is Op.CONSENT_WITHDRAW and o.payload().get("for") == slug
        ]
        if not withdrawals:
            out.append(
                self._activity_diag(
                    activity,
                    "consent-withdrawal-missing",
                    f"no touchpoint offers `consent_withdraw: {{for: {slug}}}` "
                    "(Art. 7(3))",
                )
            )
        return out

    def _objection_check(self, activity: Activity) -> list[Diagnostic]:
        """Art. 21: legitimate interests need a way to object."""
        refs = activity.derived.pii_data
        if not refs:
            return []
        objections = [
            tp for ref in refs for tp, o in self.ops.get(ref, []) if o.op is Op.OBJECT
        ]
        manual = any(
            isinstance(row.rights.get(Right.OBJECT), Exemption)
            for ref in refs
            if (row := self.rows.get(ref)) is not None and row.rights is not None
        )
        if objections or manual:
            return []
        return [
            self._activity_diag(
                activity,
                "objection-missing",
                "legitimate_interests but no `object` op on any of its items (Art. 21)",
            )
        ]

    def _dpia_check(self, activity: Activity) -> list[Diagnostic]:
        dpia = activity.derived.dpia
        if dpia is None or dpia.value not in ("always", "large_scale"):
            return []
        if activity.spec.dpia_reference is not None:
            return []
        return [
            self._activity_diag(
                activity,
                "dpia-missing",
                f"DPIA trigger `{dpia.value}` (Art. 35) but no `dpia_reference`",
            )
        ]

    def _activity_diag(
        self,
        activity: Activity,
        code: str,
        message: str,
        *,
        hint: str | None = None,
        severity: Severity = Severity.WARNING,
    ) -> Diagnostic:
        return Diagnostic(
            severity,
            code,
            f"{activity.path.name}: {message}",
            "shared",
            activity.path,
            subject=f"activities/{activity.slug}",
            hint=hint,
        )

    # -- helpers ------------------------------------------------------------

    def _path(self, row: Row) -> Path:
        unit = next(u for u in self.ws.units if u.id == row.unit)
        return unit.folder / "data" / f"{row.id}.yaml"

    def _diagnostic(self, row: Row, finding: Finding) -> Diagnostic:
        origin = finding.origin or "derived"
        head = f"{finding.ref}: {finding.right.value} ({finding.article})"
        message = f"{head}: {finding.detail}"
        if finding.note:
            note = finding.note.removeprefix(AGENT_PREFIX).strip()
            message += f' "{note}"'
        message += f" [{origin}]"
        return Diagnostic(
            Severity.WARNING,
            finding.code(),
            message,
            row.unit,
            self._path(row),
            subject=f"{finding.ref}#{finding.right.value}",
            note=finding.note,
            origin=origin,
        )


def _portability_applies(bases: set[str], ops: list[tuple[Touchpoint, OpSpec]]) -> bool:
    """Art. 20: consent/contract bases, and data the subject provided.

    "Provided by the subject" is read from the code: a ``create`` op on a
    subject-facing touchpoint (not an admin screen, not a task).
    """
    if not bases & {"consent", "contract"}:
        return False
    return any(
        o.op is Op.CREATE
        and tp.facts.kind.value == "route"
        and not tp.id.startswith("admin:")
        for tp, o in ops
    )


def _is_agent(note: str | None) -> bool:
    return (note or "").lstrip().startswith(AGENT_PREFIX)


# ---------------------------------------------------------------------------
# writing
# ---------------------------------------------------------------------------


def set_right(
    path: Path,
    right: Right,
    value: Exemption | Missing,
) -> Path:
    """Write one right into the ``rights:`` block of a data file.

    The file is created when absent (a rights-only override is valid), and
    when it exists every other key is kept as written: only the ``rights``
    block is re-emitted, so a human's ``reason`` or ``contents`` survive an
    agent's flag.
    """
    from model_wtf.compliance.yaml_io import load_yaml

    text = path.read_text(encoding="utf-8") if path.exists() else ""
    raw = load_yaml(path) if text.strip() else {}
    if not isinstance(raw, dict):
        msg = f"{path.name}: expected a mapping"
        raise ValueError(msg)
    rights = dict(raw.get("rights") or {})
    rights[right.value] = value
    # Validate the merged block before touching the disk.
    RightsSpec.model_validate(rights)
    block = ["rights:"]
    for name, entry in rights.items():
        block.append(f"  {name}: {_right_text(entry)}")
    body = _strip_rights_block(text).rstrip("\n")
    out = (body + "\n" if body else "") + "\n".join(block) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(out, encoding="utf-8")
    return path


def _right_text(entry: object) -> str:
    """Flow form of one right entry: a marker tag or ``{exempt: ..., note: ...}``."""
    from model_wtf.compliance.yaml_io import marker_text

    if isinstance(entry, Marker):
        return marker_text(entry)
    ex = entry if isinstance(entry, Exemption) else Exemption.model_validate(entry)
    text = f"{{exempt: {ex.exempt.value}"
    if ex.note:
        text += f", note: {_yaml_scalar(ex.note)}"
    return text + "}"


def _strip_rights_block(text: str) -> str:
    """Remove the top-level ``rights:`` mapping (and its indented lines)."""
    out: list[str] = []
    skipping = False
    for line in text.splitlines():
        if line.startswith("rights:"):
            skipping = True
            continue
        if skipping and (line.startswith((" ", "\t")) or not line.strip()):
            continue
        skipping = False
        out.append(line)
    return "\n".join(out)


def _yaml_scalar(value: str) -> str:
    import yaml

    return yaml.safe_dump(value, width=10**6).strip().removesuffix("\n...")
