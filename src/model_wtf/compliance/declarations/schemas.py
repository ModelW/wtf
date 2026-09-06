"""Pydantic schemas for every kind of file in a ``compliance/`` folder.

Each field carries a ``title``, a ``description`` and, when it implements
a legal requirement, an ``x-reference`` (``Art. 30(1)(d)``) in its JSON
schema metadata. Renderers, annotations and the agent prompts all read
those labels from here so the wording stays consistent.

Ids are not part of any schema: they come from the file name (see
:mod:`model_wtf.compliance.declarations.ids`). A stray ``id:`` key inside
a file is rejected by the loader before validation.
"""

from __future__ import annotations

from datetime import date, datetime  # noqa: TC003 - pydantic needs runtime types
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


def ref(article: str) -> dict[str, Any]:
    """Build the ``json_schema_extra`` carrying a legal reference."""
    return {"x-reference": article}


class Strict(BaseModel):
    """Base for human/state files: unknown keys are errors.

    A typo (``lawfull_basis``) silently ignored would let a declaration
    pass a gate it should fail, so every human-authored kind forbids
    extras. Generated files are the exception (see :class:`Generated`).
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class Generated(BaseModel):
    """Base for ``*.gen.yaml`` files.

    Only the provenance marker is mandatory in this slice; the per-kind
    fact schemas land with the extractors, so extras are allowed rather
    than failing on facts this version does not know yet.
    """

    model_config = ConfigDict(extra="allow")

    by: Literal["agent", "extractor"] = Field(
        title="Author",
        description="Which machine wrote this file: an extractor or an agent.",
    )


# ---------------------------------------------------------------------------
# Shared building blocks
# ---------------------------------------------------------------------------


class Contact(Strict):
    """Postal + electronic contact details of a legal person."""

    address: str = Field(title="Postal address", description="Full postal address.")
    email: str = Field(title="Email", description="Contact email address.")
    phone: str | None = Field(
        default=None, title="Phone", description="Contact phone number."
    )


class ContactBlock(Strict):
    """A named party with contact details (DPO, representative, ...)."""

    name: str = Field(title="Name", description="Legal or personal name.")
    contact: Contact = Field(title="Contact", description="How to reach them.")


class ExpiryAction(StrEnum):
    """What happens to the data when its retention clock expires."""

    DELETE = "delete"
    ANONYMIZE = "anonymize"


class Retention(Strict):
    """One erasure time limit attached to a data object or recipient."""

    time_limit: str = Field(
        title="Time limit",
        description=("ISO-8601 duration (P10Y) or the criteria used to determine it."),
        json_schema_extra=ref("Art. 30(1)(f)"),
    )
    trigger: str = Field(
        title="Trigger",
        description="The event that starts the retention clock.",
    )
    statutory_basis: str | None = Field(
        default=None,
        title="Statutory basis",
        description="Legal ground overriding erasure when the limit is long.",
        json_schema_extra=ref("Art. 17(3)"),
    )
    expiry_action: ExpiryAction = Field(
        title="Expiry action",
        description="Whether rows are deleted or anonymised at expiry.",
    )


class Evaluated(Strict):
    """Provenance of a machine evaluation (which commit, model, when)."""

    sha: str = Field(title="Commit", description="Git SHA that was evaluated.")
    model: str = Field(title="Model", description="LLM or engine identifier.")
    at: datetime = Field(title="Timestamp", description="When it was evaluated.")
    by: Literal["engine", "agent"] = Field(
        default="agent",
        title="Evaluator",
        description="``engine`` for deterministic gates, ``agent`` for the LLM.",
    )


# ---------------------------------------------------------------------------
# Singletons: the controller and the security description
# ---------------------------------------------------------------------------


class Controller(Strict):
    """Identity of the controller and its mandatory contacts."""

    name: str = Field(
        title="Controller",
        description="Legal name of the controller.",
        json_schema_extra=ref("Art. 30(1)(a)"),
    )
    contact: Contact = Field(
        title="Contact",
        description="Contact details of the controller.",
        json_schema_extra=ref("Art. 30(1)(a)"),
    )
    dpo: ContactBlock | None = Field(
        default=None,
        title="Data protection officer",
        description="DPO name and contact, where one is designated.",
        json_schema_extra=ref("Art. 37"),
    )
    representative: ContactBlock | None = Field(
        default=None,
        title="Representative",
        description="EU representative of a non-EU controller.",
        json_schema_extra=ref("Art. 27"),
    )
    joint_controllers: list[ContactBlock] = Field(
        default_factory=list,
        title="Joint controllers",
        description="Other controllers jointly determining the processing.",
        json_schema_extra=ref("Art. 26"),
    )


class Security(Strict):
    """General description of technical and organisational measures."""

    general_description: str = Field(
        title="Security measures",
        description="Free-text general description of the TOMs in place.",
        json_schema_extra=ref("Art. 30(1)(g)"),
    )


# ---------------------------------------------------------------------------
# actors/ and assumptions/
# ---------------------------------------------------------------------------


class Actor(Strict):
    """A category of data subjects (customers, employees, visitors...)."""

    name: str = Field(
        title="Category",
        description="Human name of the data-subject category.",
        json_schema_extra=ref("Art. 30(1)(c)"),
    )
    description: str | None = Field(
        default=None,
        title="Description",
        description="Who falls in this category and how they interact.",
    )


class Assumption(Strict):
    """A fact about the environment that findings may rely on."""

    summary: str = Field(
        title="Summary", description="One-line statement of the assumption."
    )
    description: str | None = Field(
        default=None,
        title="Description",
        description="Why the assumption holds and what would invalidate it.",
    )
    review_by: date | None = Field(
        default=None,
        title="Review by",
        description="Date by which the assumption must be re-confirmed.",
    )


# ---------------------------------------------------------------------------
# recipients/
# ---------------------------------------------------------------------------


class RecipientKind(StrEnum):
    """Legal role of a recipient."""

    PROCESSOR = "processor"
    THIRD_PARTY = "third_party"
    INTERNAL = "internal"


class Recipient(Strict):
    """A party personal data is disclosed to.

    "``dpa_reference`` required for processors" and "``transfer_safeguards``
    required with ``third_country``" are *gates* (``GDPR-PROCESSOR-DPA``,
    ``GDPR-TRANSFER``), not schema errors: a missing DPA is an open finding
    to fix or accept, not a malformed file.
    """

    drafted_by: Literal["agent"] | None = Field(
        default=None,
        title="Drafted by",
        description="Set when the agent wrote the first version.",
    )
    name: str = Field(
        title="Recipient",
        description="Entity or category name.",
        json_schema_extra=ref("Art. 30(1)(d)"),
    )
    kind: RecipientKind = Field(
        title="Kind",
        description="Processor, independent third party, or internal team.",
        json_schema_extra=ref("Art. 30(1)(d)"),
    )
    dpa_reference: str | None = Field(
        default=None,
        title="DPA reference",
        description="Where the data processing agreement lives.",
        json_schema_extra=ref("Art. 28(3)"),
    )
    third_country: str | None = Field(
        default=None,
        title="Third country",
        description="ISO code of the non-EU country the data is sent to.",
        json_schema_extra=ref("Art. 30(1)(e)"),
    )
    transfer_safeguards: str | None = Field(
        default=None,
        title="Transfer safeguards",
        description="Adequacy decision, SCCs, DPF certification...",
        json_schema_extra=ref("Art. 44-49"),
    )
    retention: list[Retention] = Field(
        default_factory=list,
        title="Retention",
        description="Time limits for sinks that keep data (Sentry, logs).",
        json_schema_extra=ref("Art. 30(1)(f)"),
    )


# ---------------------------------------------------------------------------
# processing/
# ---------------------------------------------------------------------------


class LawfulBasis(StrEnum):
    """The six lawful bases of Art. 6(1)."""

    CONSENT = "consent"
    CONTRACT = "contract"
    LEGAL_OBLIGATION = "legal_obligation"
    VITAL = "vital"
    PUBLIC_TASK = "public_task"
    LEGITIMATE_INTEREST = "legitimate_interest"


class MembersDirective(Strict):
    """Reassign members of a generated cluster (``members: {add, remove}``)."""

    add: list[str] = Field(default_factory=list, title="Add", description="Member ids.")
    remove: list[str] = Field(
        default_factory=list, title="Remove", description="Member ids."
    )


class Activity(Strict):
    """A processing activity: purpose, basis, subjects, recipients.

    ``members`` lets humans reshape the machine-proposed cluster: a
    ``{add, remove}`` mapping on the twin of a generated activity, or a
    plain list on a new activity that splits members off. The clustering
    step reads it; the registry does not.
    """

    members: MembersDirective | list[str] | None = Field(
        default=None,
        title="Members",
        description="Membership overrides for the clustering step.",
    )
    drafted_by: Literal["agent"] | None = Field(
        default=None,
        title="Drafted by",
        description="Set when the agent wrote the first version.",
    )
    purpose: str = Field(
        title="Purpose",
        description="Why the data is processed, in plain language.",
        json_schema_extra=ref("Art. 30(1)(b)"),
    )
    lawful_basis: LawfulBasis = Field(
        title="Lawful basis",
        description="The Art. 6(1) ground the processing relies on.",
        json_schema_extra=ref("Art. 6(1)"),
    )
    data_subject_categories: list[str] = Field(
        title="Data subject categories",
        description="Ids of actors whose data is processed.",
        json_schema_extra=ref("Art. 30(1)(c)"),
    )
    recipients: list[str] = Field(
        default_factory=list,
        title="Recipients",
        description="Ids of recipients the data is disclosed to.",
        json_schema_extra=ref("Art. 30(1)(d)"),
    )
    dpia_reference: str | None = Field(
        default=None,
        title="DPIA reference",
        description="Where the impact assessment lives, when Art. 35 applies.",
        json_schema_extra=ref("Art. 35"),
    )


# ---------------------------------------------------------------------------
# data/
# ---------------------------------------------------------------------------


class Content(Strict):
    """One thing an opaque field holds."""

    name: str = Field(title="Name", description="Label of the content.")
    item: str = Field(
        title="Data item",
        description="Vocabulary item (``email``, ``financial``, ``none``...).",
        json_schema_extra=ref("Art. 30(1)(c)"),
    )
    multi_subject: bool = Field(
        default=False,
        title="Multi-subject",
        description="May describe people other than the data subject.",
    )


class UnknownContents(StrEnum):
    """How likely an opaque field is to hold undeclared personal data."""

    NONE = "none"
    POSSIBLE = "possible"
    LIKELY = "likely"


class ScalarField(Strict):
    """A field holding exactly one data item (``{item: email}``)."""

    item: str = Field(
        title="Data item",
        description="Vocabulary item held by the field.",
        json_schema_extra=ref("Art. 30(1)(c)"),
    )


class OpaqueField(Strict):
    """A JSON/blob/text field declaring *what* it holds, not where."""

    contents: list[Content] = Field(
        title="Contents",
        description="Flat list of what the field holds.",
        json_schema_extra=ref("Art. 30(1)(c)"),
    )
    unknown_contents: UnknownContents = Field(
        default=UnknownContents.NONE,
        title="Unknown contents",
        description="Likelihood of personal data beyond the declared list.",
    )


class Identification(StrEnum):
    """How directly the data object points at a person."""

    IDENTIFIED = "identified"
    PSEUDONYMOUS = "pseudonymous"
    NONE = "none"


class Rectification(StrEnum):
    """How a subject gets their data corrected."""

    SELF_SERVICE = "self_service"
    DPO = "dpo"


DataField = Annotated[ScalarField | OpaqueField, Field(union_mode="left_to_right")]


class DataObject(Strict):
    """A subject-facing unit of personal data bound to code.

    The first and only mandatory answer is ``personal_data``. A model that
    holds none (a lookup table, a Wagtail workflow, a permission) is fully
    declared with ``personal_data: false`` and a ``description``; every
    other field -- and every other GDPR rule -- only matters when it does.
    """

    drafted_by: Literal["agent"] | None = Field(
        default=None,
        title="Drafted by",
        description="Set when the agent wrote the first version.",
    )
    personal_data: bool = Field(
        default=True,
        title="Personal data",
        description="Whether the object holds data about identifiable people.",
        json_schema_extra=ref("Art. 4(1)"),
    )
    name: str | None = Field(
        default=None,
        title="Name",
        description="Subject-facing noun (``Your invoices``).",
    )
    description: str = Field(
        title="Description", description="What the object contains, for subjects."
    )
    fields: dict[str, DataField] = Field(
        default_factory=dict,
        title="Fields",
        description="Per source field: the data items it holds.",
        json_schema_extra=ref("Art. 30(1)(c)"),
    )
    subject_categories: list[str] = Field(
        default_factory=list,
        title="Subject categories",
        description="Ids of actors the object describes.",
        json_schema_extra=ref("Art. 30(1)(c)"),
    )
    identification: Identification | None = Field(
        default=None,
        title="Identification",
        description="Identified, pseudonymous, or not linkable to a person.",
        json_schema_extra=ref("Art. 11"),
    )
    rectification: Rectification | None = Field(
        default=None,
        title="Rectification",
        description="Self-service in the product or via the DPO.",
        json_schema_extra=ref("Art. 16"),
    )
    multi_subject: bool = Field(
        default=False,
        title="Multi-subject",
        description="The object may hold other people's data.",
    )
    retention: list[Retention] = Field(
        default_factory=list,
        title="Retention",
        description="Erasure time limits, one per clock.",
        json_schema_extra=ref("Art. 30(1)(f)"),
    )

    @model_validator(mode="after")
    def _personal_data_needs_the_rest(self) -> DataObject:
        """Personal data must be fully described; non-personal data must not."""
        if self.personal_data:
            missing = [
                k
                for k, v in (
                    ("name", self.name),
                    ("fields", self.fields),
                    ("subject_categories", self.subject_categories),
                    ("identification", self.identification),
                    ("rectification", self.rectification),
                )
                if not v
            ]
            if missing:
                msg = f"personal data object needs {', '.join(missing)}"
                raise ValueError(msg)
        elif any(
            (isinstance(spec, ScalarField) and spec.item != "none")
            or (
                isinstance(spec, OpaqueField)
                and any(c.item != "none" for c in spec.contents)
            )
            for spec in self.fields.values()
        ):
            msg = "personal_data: false but fields carry personal-data items"
            raise ValueError(msg)
        return self


# ---------------------------------------------------------------------------
# elements/ (checkpoint ledger) and findings/
# ---------------------------------------------------------------------------


class CheckpointStatus(StrEnum):
    """Lifecycle state of one (element, rule) checkpoint."""

    UNKNOWN = "unknown"
    OK = "ok"
    NOT_OK = "not_ok"
    N_A = "n_a"
    ACCEPTED = "accepted"


class Checkpoint(Strict):
    """One ledger entry: the verdict on a rule for an element."""

    status: CheckpointStatus = Field(
        title="Status", description="Current verdict on this checkpoint."
    )
    evaluated: Evaluated | None = Field(
        default=None,
        title="Evaluated",
        description="Provenance of the last evaluation.",
    )
    depends_on: list[str] = Field(
        default_factory=list,
        title="Depends on",
        description="Paths (``file`` or ``file#symbol``) whose change re-stages.",
    )
    evidence: str | None = Field(
        default=None, title="Evidence", description="Why the checkpoint is ok."
    )
    reason: str | None = Field(
        default=None,
        title="Reason",
        description="Why the rule does not apply (``n_a``).",
    )
    finding: str | None = Field(
        default=None,
        title="Finding",
        description="``F-NNNN`` describing the failure (``not_ok``/``accepted``).",
    )
    staged_because: str | None = Field(
        default=None,
        title="Staged because",
        description="Why the checkpoint went back to ``unknown``.",
    )
    rule_version: int | None = Field(
        default=None,
        title="Rule version",
        description="Knowledge version of the rule when last evaluated.",
    )


class Ledger(Strict):
    """The ``elements/<id>.yaml`` file: rule id → checkpoint."""

    model_config = ConfigDict(extra="allow")

    @model_validator(mode="before")
    @classmethod
    def _entries_are_checkpoints(cls, data: Any) -> Any:
        """Validate every top-level key as a :class:`Checkpoint`.

        Rule ids are open-ended (any Knowledge rule), so the mapping is
        modelled as extras and validated by hand rather than as a fixed
        set of fields.
        """
        if not isinstance(data, dict):
            return data
        return {key: Checkpoint.model_validate(value) for key, value in data.items()}

    @property
    def checkpoints(self) -> dict[str, Checkpoint]:
        """The validated entries, keyed by rule id."""
        return {
            key: value
            for key, value in (self.model_extra or {}).items()
            if isinstance(value, Checkpoint)
        }


class Accepted(Strict):
    """Human acceptance of a finding, with an expiry."""

    justification: str = Field(
        title="Justification", description="Why the risk is accepted."
    )
    assumption: str | None = Field(
        default=None,
        title="Assumption",
        description="Id of the assumption the acceptance relies on.",
    )
    review_by: date = Field(
        title="Review by", description="Date after which the acceptance is stale."
    )


class Finding(Strict):
    """``findings/F-NNNN.yaml``: one failed checkpoint, as a work item."""

    checkpoint: str = Field(
        title="Checkpoint",
        description="``RULE@element`` this finding belongs to.",
    )
    severity: str = Field(
        title="Severity", description="Rule severity at evaluation time."
    )
    summary: str = Field(title="Summary", description="One-line description.")
    detail: str = Field(
        title="Detail", description="What was found, with code locations."
    )
    remediation: str = Field(
        title="Remediation", description="How to make the checkpoint pass."
    )
    references: list[str] = Field(
        default_factory=list,
        title="References",
        description="CAPEC ids, articles, links.",
    )
    provenance: list[str] = Field(
        default_factory=list,
        title="Provenance",
        description="``path:line`` locations the finding points at.",
    )
    evaluated: Evaluated = Field(
        title="Evaluated", description="Provenance of the evaluation."
    )
    accepted: Accepted | None = Field(
        default=None,
        title="Accepted",
        description="Human acceptance block, when the risk is accepted.",
    )
