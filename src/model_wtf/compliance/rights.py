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

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, model_validator

from model_wtf.compliance.ops import Op, RetentionPurge
from model_wtf.compliance.report import Diagnostic, Severity
from model_wtf.compliance.touchpoints import Kind, Scope
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
    """Computed from other data (a total, a "who did it" reference): nothing
    to rectify, port or show on its own; the source data carries the right."""

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
    Ground.DERIVED: frozenset({Right.ACCESS, Right.RECTIFY, Right.PORTABILITY}),
}
"""Grounds that only make sense for some rights; the others apply to any."""

_CASCADE_NOTE = re.compile(r"CASCADE|SET_NULL|cascad|nulled|deleted with", re.I)
"""A ``contract_active`` note naming the database path that ends the row."""

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
    UNKNOWN = "unknown"
    """Cannot be decided yet: a question for a human (a party's country)."""
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
_FACT_FOR = {
    Right.ACCESS: Op.READ,
    Right.RECTIFY: Op.UPDATE,
    Right.ERASE: Op.DELETE,
    Right.PORTABILITY: Op.PORTABILITY,
}
"""The fact that, performed on a *subject* touchpoint, serves each right: the
person reading their own data is access, changing it is rectification,
removing it is erasure."""


class _Derivation:
    def __init__(self, ws: Workspace) -> None:
        self.ws = ws
        self.rows = ws.rows
        self.adequacy = ws.knowledge.adequacy
        self.subject_scopes: frozenset[Scope] = frozenset({Scope.SUBJECT})
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
            diagnostics.extend(self._manual_reviews(row))
            for finding in item.findings:
                if finding.status is RightStatus.MISSING:
                    diagnostics.append(self._diagnostic(row, finding))
                elif finding.status is RightStatus.UNKNOWN:
                    diagnostics.append(
                        Diagnostic(
                            Severity.WARNING,
                            "todo",
                            f"{ref}: {finding.detail}",
                            row.unit,
                            self._path(row),
                            subject=f"{ref}#{finding.right.value}",
                            hint="fill the party's country in compliance/parties/",
                        )
                    )
        diagnostics.extend(self._unused_parties())
        return diagnostics, items

    def _unused_parties(self) -> list[Diagnostic]:
        """A party file nothing refers to is a question: a transfer the
        reviewer forgot to declare, or a vendor listed "just in case"
        (every oEmbed provider a library knows about) to delete."""
        used: set[str] = set()
        app = self.ws.app
        if app is not None:
            used.update(
                ref for ref in (app.controller, app.processor) if isinstance(ref, str)
            )
        for tp in self.ws.all_touchpoints.values():
            used.update(t.party for t in tp.transfers)
        for activity in self.ws.activities.items.values():
            spec = activity.spec
            used.update(spec.recipients)
            used.update(
                ref for ref in (spec.controller, spec.processor) if isinstance(ref, str)
            )
        parties_dir = self.ws.shared / "parties"
        return [
            Diagnostic(
                Severity.WARNING,
                "todo",
                f"parties/{party_id}.yaml: no transfer, activity or role refers "
                "to this party",
                "shared",
                parties_dir / f"{party_id}.yaml",
                subject=f"parties/{party_id}.yaml",
                hint="declare the transfer that sends it data, or delete the file",
            )
            for party_id in sorted(set(self.ws.parties) - used)
        ]

    def _manual_reviews(self, row: Row) -> list[Diagnostic]:
        """One Review line per right resting on a ``manual`` ground."""
        if row.rights is None:
            return []
        return [
            Diagnostic(
                Severity.WARNING,
                "manual-exemption",
                f"{row.full_id}: {right.value} handled outside the code ({value.note})",
                row.unit,
                self._path(row),
                subject=f"{row.full_id}#{right.value}",
                hint="confirm the process still exists",
            )
            for right in Right
            if isinstance(value := row.rights.get(right), Exemption)
            and value.exempt is Ground.MANUAL
        ]

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
        # Whose data is it? When every activity holding the item is about
        # staff (audit trails, editing sessions, CMS comments), the back-office
        # IS the person's own interface: a staff read is the subject's access.
        self.subject_scopes = _subject_scopes(activities)
        if not row.transient:
            # Nothing is kept for a transient item: storage-side rights do
            # not arise, only what leaves (transfers) does.
            provided = _provided_by_subject(self.ops.get(ref, []), self.subject_scopes)
            for right in (Right.ACCESS, Right.ERASE, Right.RETENTION):
                out.findings.append(self._simple(row, right, bases))
            # Rectification and portability are about what the person gave:
            # a total the system computed or an operator's note is not theirs
            # to correct or take away (Art. 16 "inaccurate", Art. 20 "provided").
            if provided:
                out.findings.append(self._simple(row, Right.RECTIFY, bases))
            access = next(f for f in out.findings if f.right is Right.ACCESS)
            if (
                provided
                and bases & {"consent", "contract"}
                # Portability presupposes access: one gap, not two.
                and access.status is not RightStatus.MISSING
            ):
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
            # An exemption explains why the right is *not* served; when the
            # code does serve it, the fact wins over the excuse.
            served = self._from_ops(row, right, article)
            if served.status is RightStatus.SATISFIED:
                return served
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
            op = _FACT_FOR.get(right)
            staff = [
                tp
                for tp, o in self.ops.get(ref, [])
                if op is not None and o.op is op and tp.scope is Scope.STAFF
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
            # The contract ends somewhere: a system/staff delete, a purge, or
            # a database cascade from the parent row (what a library note
            # describes; the framework's FK is the code path).
            closing = [
                tp
                for tp, o in self.ops.get(ref, [])
                if (o.op is Op.DELETE and tp.scope is not Scope.SUBJECT)
                or o.op is Op.RETENTION_PURGE
            ]
            cascade = bool(
                re.search(
                    r"CASCADE|SET_NULL|cascad|nulled|deleted with", ex.note or "", re.I
                )
            )
            if not closing and not cascade:
                return Finding(
                    ref,
                    right,
                    RightStatus.MISSING,
                    article,
                    "exempt contract_active but nothing deletes the data when the "
                    "contract ends (no system/staff delete, no purge)",
                    "derived",
                )
            if closing:
                names = ", ".join(t.full_id for t in closing)
                detail += f", removed at end of contract by {names}"
        return Finding(ref, right, RightStatus.EXEMPT, article, detail)

    def _from_ops(self, row: Row, right: Right, article: str) -> Finding:
        ref = row.full_id
        declared = self.ops.get(ref, [])
        if right is Right.RETENTION:
            return self._retention(ref, article, declared)
        fact = _FACT_FOR[right]
        subject = [
            (tp, o)
            for tp, o in declared
            if o.op is fact and tp.scope in self.subject_scopes
        ]
        if right is Right.ERASE and subject:
            modes = {o.payload().get("mode", "delete") for _, o in subject}
            grounds = row.rights.get(Right.ERASE) if row.rights is not None else None
            if modes == {"anonymise"} and not isinstance(grounds, Exemption):
                return Finding(
                    ref,
                    right,
                    RightStatus.MISSING,
                    article,
                    "anonymisation without a ground to keep the row "
                    "(add rights.erase exempt legal_obligation|legal_claims)",
                    "derived",
                )
        if subject:
            by = ", ".join(tp.full_id for tp, _ in subject)
            return Finding(ref, right, RightStatus.SATISFIED, article, f"by {by}")
        if right is Right.PORTABILITY:
            # Art. 20 asks for a structured, machine-readable copy: a JSON
            # API the person calls on their own data is exactly that.
            api_reads = [
                tp
                for tp, o in declared
                if o.op is Op.READ
                and tp.scope in self.subject_scopes
                and tp.facts.kind is Kind.ROUTE
                and tp.facts.framework in ("ninja", "drf")
            ]
            if api_reads:
                return Finding(
                    ref,
                    right,
                    RightStatus.SATISFIED,
                    article,
                    "as JSON via " + ", ".join(t.full_id for t in api_reads),
                )
        if right is Right.RECTIFY:
            # Immutable records the person can delete and re-create (an
            # address book, a saved card): correcting = replacing.
            mine = [(tp, o) for tp, o in declared if tp.scope in self.subject_scopes]
            creates = [tp.full_id for tp, o in mine if o.op is Op.CREATE]
            deletes = [tp.full_id for tp, o in mine if o.op is Op.DELETE]
            if creates and deletes:
                return Finding(
                    ref,
                    right,
                    RightStatus.SATISFIED,
                    article,
                    f"by re-creation: delete via {', '.join(deletes)}, create via "
                    f"{', '.join(creates)}",
                )
        staff = [
            tp
            for tp, o in declared
            if o.op is fact
            and tp.scope is Scope.STAFF
            and Scope.STAFF not in self.subject_scopes
        ]
        if staff:
            # Staff can do it on request: acceptable, but say so — the human
            # confirms there is a process (or marks it exempt staff_only).
            by = ", ".join(t.full_id for t in staff)
            return Finding(
                ref,
                right,
                RightStatus.MISSING,
                article,
                f"no self-service; staff can via {by} (exempt staff_only if a "
                "request process exists)",
                "derived",
            )
        verb = {
            Right.ACCESS: "shows it to the person",
            Right.RECTIFY: "lets the person change it",
            Right.ERASE: "lets the person delete it",
            Right.PORTABILITY: "hands the person a copy",
        }[right]
        return Finding(
            ref, right, RightStatus.MISSING, article, f"nothing {verb}", "derived"
        )

    def _retention(
        self, ref: str, article: str, declared: list[tuple[Touchpoint, OpSpec]]
    ) -> Finding:
        """Storage limitation: every row must have an end of life.

        Purge cases (``when``) cover some rows; a system/staff delete or a
        subject delete ends the others when the account or the order goes.
        With only partial cases the finding names what is still unbounded.
        """
        purges = [(tp, o) for tp, o in declared if isinstance(o, RetentionPurge)]
        deletes = [tp for tp, o in declared if o.op is Op.DELETE]
        cases = [f"{o.sentence()} ({tp.full_id})" for tp, o in purges]
        general = [tp for tp, o in purges if not o.when]
        if general or (purges and deletes):
            return Finding(
                ref, Right.RETENTION, RightStatus.SATISFIED, article, "; ".join(cases)
            )
        if purges:
            return Finding(
                ref,
                Right.RETENTION,
                RightStatus.MISSING,
                article,
                "; ".join(cases)
                + "; the other rows are kept forever (no purge, no delete)",
                "derived",
            )
        if deletes:
            by = ", ".join(t.full_id for t in deletes)
            return Finding(
                ref,
                Right.RETENTION,
                RightStatus.SATISFIED,
                article,
                f"removed on request/event by {by}; no time-based purge",
            )
        return Finding(
            ref,
            Right.RETENTION,
            RightStatus.MISSING,
            article,
            "kept forever: no purge task, nothing deletes it",
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
        declared = row.rights.get(Right.TRANSFER) if row.rights is not None else None
        if not sent_to and not isinstance(declared, Missing):
            return None
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
        unknown: list[str] = []
        for slug in sent_to:
            party = parties.get(slug)
            if party is None:
                continue
            country = party.country if isinstance(party.country, str) else None
            if country is None:
                unknown.append(slug)
                continue
            if country.upper() in self.adequacy:
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
        if unknown:
            return Finding(
                ref,
                Right.TRANSFER,
                RightStatus.UNKNOWN,
                "Ch. V",
                "sent to " + ", ".join(unknown) + " whose country is !todo",
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
        # An opt-out is a subject-facing update or delete on one of the items.
        objections = [
            tp
            for ref in refs
            for tp, o in self.ops.get(ref, [])
            if o.op in (Op.UPDATE, Op.DELETE) and tp.scope is Scope.SUBJECT
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
                "legitimate_interests but nothing lets the person opt out "
                "(no subject-facing update/delete on its items, Art. 21)",
            )
        ]

    def _dpia_check(self, activity: Activity) -> list[Diagnostic]:
        """Art. 35: ``always`` (special categories) is a gap; ``large_scale``
        depends on volume the code cannot tell — a question for a human."""
        dpia = activity.derived.dpia
        if dpia is None or dpia.value == "never":
            return []
        if activity.spec.dpia_reference is not None:
            return []
        if dpia.value == "always":
            return [
                self._activity_diag(
                    activity,
                    "dpia-missing",
                    "special-category data (Art. 35) but no `dpia_reference`",
                )
            ]
        # Confidential data only triggers a DPIA at large scale, which is
        # a product-level answer (app.yaml), not one per activity.
        large_scale = self.ws.large_scale
        if large_scale is False:
            return []
        if large_scale is True:
            return [
                self._activity_diag(
                    activity,
                    "dpia-missing",
                    "confidential data processed at large scale (app.yaml "
                    "large_scale: true, Art. 35) but no `dpia_reference`",
                )
            ]
        # ``!todo``: the question is already asked once on app.yaml.
        return []

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


STAFF_SUBJECTS = frozenset({"staff", "employees", "operators", "editors", "admins"})
"""``data_subjects`` values meaning the people are the organisation's own
workers, whose interface to their data is the back-office."""


def _subject_scopes(activities: list[Activity]) -> frozenset[Scope]:
    """Which touchpoint scopes act *as the person* for these activities."""
    subjects = {
        s.lower()
        for a in activities
        if not isinstance(a.spec.data_subjects, Marker)
        for s in a.spec.data_subjects
    }
    if subjects and subjects <= STAFF_SUBJECTS:
        return frozenset({Scope.SUBJECT, Scope.STAFF})
    return frozenset({Scope.SUBJECT})


def _provided_by_subject(
    ops: list[tuple[Touchpoint, OpSpec]], subject_scopes: frozenset[Scope]
) -> bool:
    """Whether the person typed the value in: a ``create`` (or ``update``) on a
    touchpoint they use themselves — not an admin screen, not a task."""
    scopes = subject_scopes | {Scope.PUBLIC}
    return any(o.op in (Op.CREATE, Op.UPDATE) and tp.scope in scopes for tp, o in ops)


def is_agent_note(note: str | None) -> bool:
    """Whether an agent wrote the note (``[agent]`` prefix)."""
    return (note or "").lstrip().startswith(AGENT_PREFIX)


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
