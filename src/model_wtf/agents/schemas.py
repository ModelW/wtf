"""Output schemas of the ``auto`` sub-agents, one per stage.

The agents are the labour, not the authority: whatever they return is
validated against these models before model-wtf writes a single file. The
JSON schema of each model is injected verbatim into the agent's prompt, so
the prompt and the validator can never drift apart.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from model_wtf.compliance.declarations.schemas import (  # noqa: TC001 - runtime
    CheckpointStatus,
    Identification,
    LawfulBasis,
    RecipientKind,
    UnknownContents,
)


class AgentOutput(BaseModel):
    """Base: extras forbidden so hallucinated keys fail loudly."""

    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------------


class DiscoveredRoute(AgentOutput):
    """An HTTP entrypoint seen in the code."""

    method: str = Field(description="HTTP verb, upper-case (GET, POST, ...).")
    path: str = Field(description="URL path as mounted (/back/api/leads/).")
    auth: Literal["none", "session", "token", "admin", "unknown"] = Field(
        description="Best guess of the authentication the route requires."
    )
    provenance: str = Field(description="path:line of the handler definition.")


class DiscoveredField(AgentOutput):
    """One model field."""

    name: str
    type: str = Field(description="Field class (CharField, JSONField, ...).")
    opaque: bool = Field(
        default=False,
        description="JSON/blob/text field whose contents the schema does not show.",
    )
    candidate_contents: list[str] = Field(
        default_factory=list,
        description=(
            "For opaque fields: keys or things seen stored there in serializers, "
            "tests, fixtures or callers (address, iban, utm_campaign...)."
        ),
    )


class DiscoveredModel(AgentOutput):
    """A persisted model / table."""

    id: str = Field(description="app_label.ModelName (Django) or table name.")
    fields: list[DiscoveredField]
    provenance: str = Field(description="path:line of the model definition.")
    soft_delete: bool = False
    history: bool = Field(
        default=False, description="History/audit copies kept (simple_history...)."
    )


class DiscoveredTask(AgentOutput):
    """A background task / scheduled job."""

    id: str = Field(description="Dotted path of the task function.")
    scheduled: str | None = Field(
        default=None, description="Schedule expression if periodic, else null."
    )
    provenance: str


class DiscoveredEgress(AgentOutput):
    """A third party the code talks to."""

    slug: str = Field(description="Short id (stripe, sentry, mailchimp).")
    sdks: list[str] = Field(default_factory=list, description="Packages imported.")
    hosts: list[str] = Field(default_factory=list, description="Hosts called.")
    env_keys: list[str] = Field(
        default_factory=list, description="Environment variables holding its keys."
    )
    provenance: list[str] = Field(default_factory=list)


class DiscoverOutput(AgentOutput):
    """What ``discover`` returns for one unit."""

    stack: list[str] = Field(
        description="Stacks detected: django, ninja, drf, wagtail, sveltekit, ..."
    )
    routes: list[DiscoveredRoute]
    models: list[DiscoveredModel]
    tasks: list[DiscoveredTask]
    egress: list[DiscoveredEgress]


# ---------------------------------------------------------------------------
# classify
# ---------------------------------------------------------------------------


class ClassifiedContent(AgentOutput):
    """One thing an opaque field holds."""

    name: str
    item: str = Field(description="A data-items vocabulary item, or 'none'.")
    multi_subject: bool = False


class ClassifiedField(AgentOutput):
    """Classification of one field."""

    name: str
    item: str | None = Field(
        default=None, description="Vocabulary item for a scalar field."
    )
    contents: list[ClassifiedContent] | None = Field(
        default=None, description="For opaque fields: what they hold."
    )
    unknown_contents: UnknownContents | None = Field(
        default=None, description="For opaque fields: likelihood of more PII."
    )


class ClassifyDataObjectOutput(AgentOutput):
    """Draft of ``data/<id>.yaml``."""

    name: str = Field(description="Subject-facing noun (Your invoices).")
    description: str
    fields: list[ClassifiedField]
    subject_categories: list[str] = Field(description="Actor ids.")
    identification: Identification
    multi_subject: bool = False
    rationale: str = Field(description="One paragraph: why these items.")


class ClassifyRecipientOutput(AgentOutput):
    """Draft of ``recipients/<id>.yaml``."""

    name: str
    kind: RecipientKind
    third_country: str | None = Field(
        default=None, description="ISO code when outside the EU/EEA."
    )
    typical_items: list[str] = Field(
        default_factory=list, description="Vocabulary items sent there."
    )
    rationale: str


class ClassifyActivityOutput(AgentOutput):
    """Draft of ``processing/<id>.yaml``."""

    purpose: str = Field(description="Specific, at least a dozen words.")
    lawful_basis: LawfulBasis
    data_subject_categories: list[str] = Field(description="Actor ids.")
    recipients: list[str] = Field(default_factory=list, description="Recipient ids.")
    dpia_needed: bool = Field(description="Art. 35(3) heuristics say a DPIA is due.")
    dpia_reason: str | None = None
    rationale: str


# ---------------------------------------------------------------------------
# evaluate
# ---------------------------------------------------------------------------


class EvaluateFinding(AgentOutput):
    """Body of the finding when the checkpoint fails."""

    severity: Literal["low", "medium", "high", "critical"] | None = Field(
        default=None,
        description="Omit to use the rule's severity; may not be lower than it.",
    )
    summary: str = Field(description="One line, actionable.")
    detail: str = Field(description="What was found, with path:line references.")
    remediation: str = Field(description="How to make the checkpoint pass.")
    references: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(description="path:line locations, at least one.")


class EvaluateOutput(AgentOutput):
    """Verdict on one checkpoint."""

    status: Literal[CheckpointStatus.OK, CheckpointStatus.NOT_OK, CheckpointStatus.N_A]
    evidence: str | None = Field(
        default=None, description="Required for ok: what proves it, with paths."
    )
    reason: str | None = Field(
        default=None, description="Required for n_a: why the rule does not apply."
    )
    depends_on: list[str] = Field(
        description=(
            "Every file you read to decide (path or path#symbol). A change to any "
            "of them re-opens this checkpoint."
        )
    )
    finding: EvaluateFinding | None = Field(
        default=None, description="Required for not_ok."
    )


# ---------------------------------------------------------------------------
# stage (the DiffStager answer)
# ---------------------------------------------------------------------------


class StagedCheckpoint(AgentOutput):
    """One checkpoint the diff plausibly invalidates."""

    checkpoint: str = Field(description="RULE@kind:id, copied from the index.")
    reason: str = Field(description="One sentence tying the hunk to the checkpoint.")


class StageOutput(AgentOutput):
    """What the staging agent returns."""

    restage: list[StagedCheckpoint]


STAGE_SCHEMAS: dict[str, type[AgentOutput]] = {
    "discover": DiscoverOutput,
    "classify-data-object": ClassifyDataObjectOutput,
    "classify-recipient": ClassifyRecipientOutput,
    "classify-activity": ClassifyActivityOutput,
    "evaluate": EvaluateOutput,
    "stage": StageOutput,
}
"""Output schema per work-item kind."""
