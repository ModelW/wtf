"""Which model runs which stage.

``knowledge/routing.yaml`` ships the defaults (cheap for classification,
strong for evaluation, OpenRouter's price/quality preset otherwise); a
repository may override any entry in ``.model-wtf.yml#routing``; the CLI's
``--model-override stage=model`` beats both.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from model_wtf.knowledge.loader import KnowledgeError, default_root

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

STAGES = ("discover", "classify", "evaluate", "stage")
"""Stages a model can be routed to (``reconcile`` is deterministic)."""

AGENT_FOR_STAGE: dict[str, list[str]] = {
    "discover": ["wtf-discover"],
    "classify": [
        "wtf-classify-data-object",
        "wtf-classify-recipient",
        "wtf-classify-activity",
    ],
    "evaluate": ["wtf-evaluate"],
    "stage": ["wtf-stage"],
}


class RoutingFile(BaseModel):
    """Shape of ``routing.yaml`` and of the ``routing:`` override block."""

    model_config = ConfigDict(extra="forbid")

    default: str | None = Field(default=None, description="provider/model")
    stages: dict[str, str] = Field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Routing:
    """Resolved routing: a default and one model per stage."""

    default: str
    stages: dict[str, str] = field(default_factory=dict)

    def model_for(self, stage: str) -> str:
        """``provider/model`` for ``stage``."""
        return self.stages.get(stage, self.default)

    def agent_models(self) -> dict[str, str]:
        """Per-agent model map for ``build_config`` (only routed stages)."""
        out: dict[str, str] = {}
        for stage, model in self.stages.items():
            for agent in AGENT_FOR_STAGE.get(stage, []):
                out[agent] = model
        return out


def load_routing(
    repo_root: Path | None = None,
    overrides: Iterable[str] = (),
    knowledge_root: Path | None = None,
) -> Routing:
    """Merge shipped defaults, the repo's ``.model-wtf.yml#routing``, CLI overrides.

    Raises
    ------
    KnowledgeError
        When a routing file is malformed or an override is not
        ``stage=provider/model`` with a known stage.
    """
    shipped = _read((knowledge_root or default_root()) / "routing.yaml")
    default = shipped.default or "openrouter/openrouter/auto"
    stages = dict(shipped.stages)

    if repo_root is not None:
        override_file = repo_root / ".model-wtf.yml"
        if override_file.is_file():
            data = yaml.safe_load(override_file.read_text(encoding="utf-8")) or {}
            block = data.get("routing") if isinstance(data, dict) else None
            if block:
                try:
                    repo = RoutingFile.model_validate(block)
                except ValidationError as exc:
                    msg = f"invalid routing in .model-wtf.yml: {exc}"
                    raise KnowledgeError(msg) from exc
                default = repo.default or default
                stages.update(repo.stages)

    for raw in overrides:
        stage, sep, model = raw.partition("=")
        if not sep or not model or stage not in (*STAGES, "default"):
            msg = (
                "--model-override expects stage=provider/model "
                f"(stages: {', '.join(STAGES)}), got {raw!r}"
            )
            raise KnowledgeError(msg)
        if stage == "default":
            default = model
        else:
            stages[stage] = model

    unknown = set(stages) - set(STAGES)
    if unknown:
        msg = f"routing names unknown stages: {', '.join(sorted(unknown))}"
        raise KnowledgeError(msg)
    return Routing(default=default, stages=stages)


def _read(path: Path) -> RoutingFile:
    if not path.is_file():
        return RoutingFile()
    try:
        return RoutingFile.model_validate(
            yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        )
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        msg = f"invalid {path}: {exc}"
        raise KnowledgeError(msg) from exc


def split_model(model: str) -> tuple[str, str]:
    """``provider/model/id`` -> ``(provider, model/id)``."""
    provider, sep, rest = model.partition("/")
    if not sep or not rest:
        msg = f"model must be provider/model, got {model!r}"
        raise KnowledgeError(msg)
    return provider, rest
