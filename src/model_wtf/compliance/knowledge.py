"""Built-in knowledge: sensitivity scale, categories of personal data, rules.

Everything lives as YAML under ``model_wtf/knowledge/`` so that it can be
read, diffed and reviewed like the declarations it classifies. A repository
may replace the sensitivity scale or the category list with its own files
(``compliance/sensitivity/``, ``compliance/categories/``); each custom entry
can say which built-in id(s) it ``replaces`` so the rules — which speak the
built-in vocabulary — still resolve.
"""

from __future__ import annotations

import re
from enum import StrEnum
from functools import cached_property
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from model_wtf.compliance.declarations import format_errors
from model_wtf.compliance.report import Diagnostic, Severity
from model_wtf.compliance.schemas import NonEmpty, StrictModel, is_valid_id
from model_wtf.compliance.yaml_io import Todo, iter_todo_paths, load_yaml

if TYPE_CHECKING:
    from collections.abc import Iterable

    from model_wtf.introspect.runner import FieldInfo

SENSITIVITY_DIR = "sensitivity"
CATEGORIES_DIR = "categories"


class Dpia(StrEnum):
    """Art. 35 hint: when does data at this level call for a DPIA."""

    NEVER = "never"
    LARGE_SCALE = "large_scale"
    ALWAYS = "always"

    @property
    def rank(self) -> int:
        """Order for ``max()``."""
        return list(Dpia).index(self)


class Legal(StrEnum):
    """Which article makes a category special."""

    NONE = "none"
    ART9 = "art9"
    ART10 = "art10"


class SensitivityLevel(StrictModel):
    """One ``sensitivity/<level>.yaml``."""

    rank: int = Field(ge=0)
    description: NonEmpty | Todo
    criteria: NonEmpty | Todo
    handling: NonEmpty | Todo
    dpia: Dpia = Dpia.NEVER
    replaces: list[str] = Field(default_factory=list)


class Category(StrictModel):
    """One ``categories/<id>.yaml``."""

    description: NonEmpty | Todo
    examples: list[str] = Field(default_factory=list)
    register_label: NonEmpty | Todo
    legal: Legal = Legal.NONE
    dpia: bool = False
    replaces: list[str] = Field(default_factory=list)


class Match(BaseModel):
    """One alternative of a rule's ``match`` list; keys are AND-ed."""

    model_config = ConfigDict(extra="forbid")

    type: list[str] | None = None
    internal_type: list[str] | None = None
    name: str | None = None
    primary_key: bool | None = None
    choices: bool | None = None

    @field_validator("name")
    @classmethod
    def _compiles(cls, value: str | None) -> str | None:
        if value is not None:
            re.compile(value)
        return value

    def matches(self, field: FieldInfo) -> bool:
        """Whether every constraint of this alternative holds for ``field``."""
        if self.type is not None and field.type not in self.type:
            return False
        if (
            self.internal_type is not None
            and field.internal_type not in self.internal_type
        ):
            return False
        if self.primary_key is not None and field.primary_key is not self.primary_key:
            return False
        if self.choices is not None and field.choices is not self.choices:
            return False
        return not (
            self.name is not None
            and re.search(self.name, field.name, re.IGNORECASE) is None
        )


class DataRule(StrictModel):
    """One ``data_rules/<id>.yaml``: a classification decided by field facts."""

    description: str
    priority: int
    match: list[Match] = Field(min_length=1)
    pii: bool
    sensitivity: str
    category: str
    assumed: bool = False

    def matches(self, field: FieldInfo) -> bool:
        """OR over the alternatives."""
        return any(alt.matches(field) for alt in self.match)


class KnowledgeError(Exception):
    """A knowledge file (built-in or custom) is invalid; carries diagnostics."""

    def __init__(self, diagnostics: list[Diagnostic]) -> None:
        super().__init__("; ".join(d.message for d in diagnostics))
        self.diagnostics = diagnostics


class Knowledge:
    """Resolved scale, categories and rules for one repository.

    Parameters
    ----------
    sensitivity
        Level id → definition, already the custom scale when the repo has one.
    categories
        Category id → definition, likewise.
    rules
        Rules sorted by ascending priority, keyed by id.
    aliases
        Built-in id → custom id, from the ``replaces`` lists.
    """

    def __init__(
        self,
        sensitivity: dict[str, SensitivityLevel],
        categories: dict[str, Category],
        rules: list[tuple[str, DataRule]],
        aliases: dict[str, str],
        todos: list[Diagnostic] | None = None,
    ) -> None:
        self.sensitivity = sensitivity
        self.categories = categories
        self.rules = sorted(rules, key=lambda pair: (pair[1].priority, pair[0]))
        self.aliases = aliases
        self.todos = todos or []
        """``!todo`` values found in the custom scale/categories."""

    @cached_property
    def default_ids(self) -> tuple[frozenset[str], frozenset[str]]:
        """Built-in (level ids, category ids)."""
        return (
            frozenset(_builtin_names(SENSITIVITY_DIR)),
            frozenset(_builtin_names(CATEGORIES_DIR)),
        )

    def resolve(self, name: str) -> str:
        """Map a built-in level/category id to its custom replacement, if any."""
        return self.aliases.get(name, name)

    def classify(self, field: FieldInfo) -> tuple[str, DataRule]:
        """First rule matching ``field`` (there is always a fallback rule)."""
        for rule_id, rule in self.rules:
            if rule.matches(field):
                return rule_id, rule
        msg = "no rule matched; the built-in fallback rule is missing"
        raise KnowledgeError([Diagnostic(Severity.ERROR, "knowledge", msg)])

    def dpia_for(self, level: str, category: str) -> Dpia:
        """Max of the level's hint and the category's flag."""
        hint = self.sensitivity[level].dpia
        if self.categories[category].dpia and hint is Dpia.NEVER:
            return Dpia.LARGE_SCALE
        return hint

    def ordered_levels(self) -> list[str]:
        """Level ids by ascending rank."""
        return sorted(self.sensitivity, key=lambda k: self.sensitivity[k].rank)


def load_knowledge(shared: Path | None) -> Knowledge:
    """Load built-ins and apply the repo's custom scale/categories if present.

    Raises
    ------
    KnowledgeError
        Built-in files must always be valid; custom files are validated with
        the same schemas and additionally must cover every built-in id
        exactly once (directly or through ``replaces``).
    """
    diagnostics: list[Diagnostic] = []
    aliases: dict[str, str] = {}

    sensitivity = _load_dir(
        _builtin_dir(SENSITIVITY_DIR), SensitivityLevel, diagnostics, "shared"
    )
    categories = _load_dir(
        _builtin_dir(CATEGORIES_DIR), Category, diagnostics, "shared"
    )
    rules_raw = _load_dir(_builtin_dir("data_rules"), DataRule, diagnostics, "shared")
    if diagnostics:
        raise KnowledgeError(diagnostics)

    if shared is not None:
        custom_levels = shared / SENSITIVITY_DIR
        if custom_levels.is_dir():
            levels = _load_dir(custom_levels, SensitivityLevel, diagnostics, "shared")
            _check_coverage(
                levels, set(sensitivity), custom_levels, "level", diagnostics
            )
            _check_unique_ranks(levels, custom_levels, diagnostics)
            aliases.update(_aliases(levels))
            sensitivity = levels
        custom_cats = shared / CATEGORIES_DIR
        if custom_cats.is_dir():
            cats = _load_dir(custom_cats, Category, diagnostics, "shared")
            _check_coverage(cats, set(categories), custom_cats, "category", diagnostics)
            aliases.update(_aliases(cats))
            categories = cats

    if any(d.severity is Severity.ERROR for d in diagnostics):
        raise KnowledgeError(diagnostics)
    return Knowledge(
        sensitivity,
        categories,
        list(rules_raw.items()),
        aliases,
        todos=[d for d in diagnostics if d.code == "todo"],
    )


def _aliases(custom: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for custom_id, entry in custom.items():
        for replaced in entry.replaces:
            out[replaced] = custom_id
    return out


def _check_coverage(
    custom: dict[str, Any],
    defaults: set[str],
    folder: Path,
    what: str,
    diagnostics: list[Diagnostic],
) -> None:
    """Every built-in id must be a custom id or replaced by exactly one."""
    covered: dict[str, list[str]] = {name: [] for name in defaults}
    for custom_id, entry in custom.items():
        if custom_id in covered:
            covered[custom_id].append(custom_id)
        for replaced in entry.replaces:
            if replaced not in covered:
                diagnostics.append(
                    Diagnostic(
                        Severity.ERROR,
                        f"{what}-replaces-unknown",
                        f"{custom_id} replaces unknown built-in {what} {replaced!r}",
                        "shared",
                        folder / f"{custom_id}.yaml",
                    )
                )
                continue
            covered[replaced].append(custom_id)
    for name, by in covered.items():
        if len(by) != 1:
            how = (
                "not covered"
                if not by
                else f"covered {len(by)} times ({', '.join(by)})"
            )
            diagnostics.append(
                Diagnostic(
                    Severity.ERROR,
                    f"{what}-coverage",
                    f"built-in {what} {name!r} is {how} by the custom {what} set",
                    "shared",
                    folder,
                )
            )


def _check_unique_ranks(
    custom: dict[str, SensitivityLevel], folder: Path, diagnostics: list[Diagnostic]
) -> None:
    seen: dict[int, str] = {}
    for level_id, level in custom.items():
        if level.rank in seen:
            diagnostics.append(
                Diagnostic(
                    Severity.ERROR,
                    "level-rank-duplicate",
                    f"levels {seen[level.rank]!r} and {level_id!r} "
                    f"share rank {level.rank}",
                    "shared",
                    folder / f"{level_id}.yaml",
                )
            )
        seen[level.rank] = level_id


def _load_dir[M: BaseModel](
    folder: Path, model: type[M], diagnostics: list[Diagnostic], scope: str
) -> dict[str, M]:
    out: dict[str, M] = {}
    for path in sorted(folder.glob("*.yaml")):
        if not is_valid_id(path.stem.replace("_", "-")):
            diagnostics.append(
                Diagnostic(
                    Severity.ERROR,
                    "invalid-id",
                    f"{path.name}: not a valid id",
                    scope,
                    path,
                )
            )
            continue
        try:
            data = load_yaml(path)
            instance = model.model_validate(data if data is not None else {})
        except (OSError, yaml.YAMLError) as exc:
            diagnostics.append(
                Diagnostic(
                    Severity.ERROR, "yaml-error", f"{path.name}: {exc}", scope, path
                )
            )
            continue
        except ValidationError as exc:
            diagnostics.extend(
                Diagnostic(
                    Severity.ERROR,
                    "schema-error",
                    f"{path.name}: {loc}: {msg}",
                    scope,
                    path,
                )
                for loc, msg in format_errors(exc)
            )
            continue
        diagnostics.extend(
            Diagnostic(
                Severity.WARNING,
                "todo",
                f"{path.name}: {dotted} is still !todo",
                scope,
                path,
            )
            for dotted in iter_todo_paths(instance)
        )
        out[path.stem] = instance
    return out


def _builtin_dir(name: str) -> Path:
    """Filesystem path of a built-in knowledge folder.

    ``resources.files`` returns a Traversable; for a regular (non-zipped)
    install it is a real path, which is what ``glob`` needs.
    """
    return Path(str(resources.files("model_wtf.knowledge").joinpath(name)))


def _builtin_names(name: str) -> Iterable[str]:
    return (p.stem for p in _builtin_dir(name).glob("*.yaml"))
