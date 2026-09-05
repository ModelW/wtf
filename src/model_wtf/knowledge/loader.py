"""Load the packaged Knowledge into validated, cross-checked objects.

The loader reads from the package's own directory by default (``files()``
keeps this working when installed as a wheel) but accepts any root, which
is how tests exercise malformed rules and how a repo could one day ship
extra rules of its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from pydantic import BaseModel, ValidationError

from model_wtf.knowledge.schemas import DataItem, Egress, Framework, Rule

if TYPE_CHECKING:
    from collections.abc import Iterable


class KnowledgeError(Exception):
    """A Knowledge file is malformed or inconsistent (a packaging bug)."""


@dataclass(frozen=True, slots=True)
class Knowledge:
    """Everything the engine needs, indexed by id."""

    rules: dict[str, Rule]
    data_items: dict[str, DataItem]
    egress: dict[str, Egress]
    frameworks: dict[str, Framework]
    root: Path = field(compare=False)

    def rules_for(self, kind: str, stacks: Iterable[str] = ()) -> list[Rule]:
        """Rules whose ``applies_to`` targets ``kind`` on ``stacks``, by id."""
        stack_set = frozenset(stacks)
        return [
            rule
            for rule in sorted(self.rules.values(), key=lambda r: r.id)
            if rule.applies_to.matches(kind, stack_set)
        ]

    def by_framework(self, framework: str | None) -> list[Rule]:
        """Rules tagged ``framework`` (``None`` / ``"all"`` → every rule)."""
        rules = sorted(self.rules.values(), key=lambda r: r.id)
        if framework in (None, "all"):
            return rules
        return [r for r in rules if framework in r.frameworks]


def default_root() -> Path:
    """The ``knowledge/`` directory shipped inside the package."""
    return Path(__file__).resolve().parent


@cache
def load_knowledge(root: Path | None = None) -> Knowledge:
    """Read and validate every Knowledge file under ``root``.

    Cached: Knowledge is immutable for the life of the process and several
    commands load it independently.

    Raises
    ------
    KnowledgeError
        On the first malformed file, duplicate id, or dangling reference
        (rule → unknown framework, egress → unknown data item).
    """
    root = (root or default_root()).resolve()
    frameworks = _load_dir(root / "frameworks", Framework)
    data_items = _load_dir(root / "data_items", DataItem)
    egress = _load_dir(root / "egress", Egress)
    rules = _load_rules(root / "rules")

    for rule in rules.values():
        for framework in rule.frameworks:
            if framework not in frameworks:
                msg = f"rule {rule.id}: unknown framework {framework!r}"
                raise KnowledgeError(msg)
    for slug, entry in egress.items():
        for item in entry.typical_items:
            if item not in data_items:
                msg = f"egress {slug}: unknown data item {item!r}"
                raise KnowledgeError(msg)

    return Knowledge(
        rules=rules,
        data_items=data_items,
        egress=egress,
        frameworks=frameworks,
        root=root,
    )


def _load_dir[M: BaseModel](directory: Path, model: type[M]) -> dict[str, M]:
    """Load ``<id>.yaml`` files of one kind; the file name is the id."""
    out: dict[str, M] = {}
    for path in sorted(directory.glob("*.yaml")) if directory.is_dir() else []:
        out[path.stem] = _read(path, model)
    return out


def _load_rules(directory: Path) -> dict[str, Rule]:
    """Load rules recursively; the in-file ``id`` must match the file name."""
    out: dict[str, Rule] = {}
    for path in sorted(directory.rglob("*.yaml")):
        rule = _read(path, Rule)
        if rule.id != path.stem:
            msg = f"{path}: id {rule.id!r} does not match file name"
            raise KnowledgeError(msg)
        if rule.id in out:
            msg = f"{path}: duplicate rule id {rule.id!r}"
            raise KnowledgeError(msg)
        out[rule.id] = rule
    return out


def _read[M: BaseModel](path: Path, model: type[M]) -> M:
    """Parse one YAML file into ``model`` or raise :class:`KnowledgeError`."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return model.model_validate(data)
    except (OSError, yaml.YAMLError) as exc:
        msg = f"cannot read {path}: {exc}"
        raise KnowledgeError(msg) from exc
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(loc) for loc in err['loc']) or '<root>'}: {err['msg']}"
            for err in exc.errors()
        )
        msg = f"invalid {path}: {details}"
        raise KnowledgeError(msg) from exc
