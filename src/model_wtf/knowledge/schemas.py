"""Shapes of the Knowledge files (rules, data items, egress, frameworks).

Unlike declaration files, Knowledge ships inside the package, so a
validation error here is a model-wtf bug rather than a user mistake. The
schemas are still strict (extras forbidden) so that a typo in a rule file
fails the test suite instead of silently disabling the rule.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RuleKind(StrEnum):
    """Who resolves the rule."""

    GATE = "gate"
    """Deterministic: a ``condition`` over the declarations decides."""

    VERIFY = "verify"
    """Needs a look at the code: the agent decides, guided by hints."""


class Severity(StrEnum):
    """Impact of a failed rule, copied onto findings."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ElementKind(StrEnum):
    """The kinds of elements a rule can target.

    Security rules attack surfaces (routes, tasks, stores, flows); GDPR
    rules attach to the registry entities (data objects, activities,
    recipients). The two sets share one engine, hence one enum.
    """

    HTTP_ROUTE = "http_route"
    WS_ROUTE = "ws_route"
    TASK = "task"
    STORE = "store"
    EGRESS = "egress"
    COMPONENT = "component"
    FLOW = "flow"
    DATA_OBJECT = "data_object"
    ACTIVITY = "activity"
    RECIPIENT = "recipient"


class AppliesTo(BaseModel):
    """Targeting clause of a rule.

    ``stack`` omitted (or empty) means "any stack"; otherwise the element
    must run on one of the listed stacks. Kind must match exactly.
    """

    model_config = ConfigDict(extra="forbid")

    kind: ElementKind
    stack: list[str] = Field(default_factory=list)

    def matches(self, kind: str, stacks: frozenset[str] | set[str]) -> bool:
        """Whether an element of ``kind`` running on ``stacks`` is targeted."""
        if self.kind.value != kind:
            return False
        return not self.stack or bool(set(self.stack) & set(stacks))


class Rule(BaseModel):
    """One rule file under ``knowledge/rules/**``."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Z][A-Z0-9-]+$")
    title: str
    frameworks: list[str] = Field(min_length=1)
    applies_to: AppliesTo
    kind: RuleKind
    severity: Severity
    version: int = Field(ge=1, description="Bump to re-stage every checkpoint.")
    description: str
    mitigation: str
    condition: str | None = Field(
        default=None,
        description="Gate expression; see the engine for the namespace.",
    )
    evidence_hints: list[str] = Field(
        default_factory=list,
        description="What the agent should look at for a verify rule.",
    )
    references: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _kind_matches_payload(self) -> Rule:
        """Gates need a condition; verify rules must not pretend to have one."""
        if self.kind is RuleKind.GATE and not self.condition:
            msg = f"{self.id}: gate rules need a 'condition'"
            raise ValueError(msg)
        if self.kind is RuleKind.VERIFY and self.condition:
            msg = f"{self.id}: verify rules cannot have a 'condition'"
            raise ValueError(msg)
        return self


class Classification(StrEnum):
    """pytm-compatible data classification, from least to most sensitive."""

    PUBLIC = "public"
    INTERNAL = "internal"
    RESTRICTED = "restricted"
    SENSITIVE = "sensitive"
    SECRET = "secret"  # noqa: S105 - a label, not a password


class DataItem(BaseModel):
    """One vocabulary entry under ``knowledge/data_items/``.

    The file name is the item (``email``), matching the ``item:`` values of
    data-object declarations. Each item carries both projections: the GDPR
    one (category, Art. 9, DPIA trigger) and the threat-model one
    (classification, PII, credentials).
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    description: str
    gdpr_category: Literal[
        "identity",
        "contact",
        "financial",
        "special",
        "profiling",
        "content",
        "none",
    ]
    special_art9: bool
    classification: Classification
    pii: bool
    credentials: bool
    dpia_trigger: bool


class EgressDetection(BaseModel):
    """Signals that a third party is in use."""

    model_config = ConfigDict(extra="forbid")

    packages: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    env: list[str] = Field(default_factory=list)


class Egress(BaseModel):
    """A known third party, under ``knowledge/egress/<slug>.yaml``.

    Used to turn "the code imports ``stripe``" into a suggested recipient
    with sensible defaults (kind, country) for the agent to draft from.
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    kind: Literal["processor", "third_party"]
    default_third_country: str | None = None
    detection: EgressDetection = Field(default_factory=EgressDetection)
    typical_items: list[str] = Field(default_factory=list)
    sink: bool = Field(
        default=False,
        description="Keeps data with its own retention (logs, analytics).",
    )
    notes: str | None = None


class Framework(BaseModel):
    """A framework tag rules can carry (``knowledge/frameworks/<id>.yaml``)."""

    model_config = ConfigDict(extra="forbid")

    name: str
    description: str
