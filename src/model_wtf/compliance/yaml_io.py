"""YAML loading with the ``!todo`` and ``!missing`` markers.

Compliance files are written by humans and agents over time. A value that
nobody has filled yet is not "absent" (that would be a schema error) and
not an empty string (that would silently pass): it is a *marker*, and the
two markers say different things:

* ``!todo`` — the analysis has not been conducted; someone still has to
  look. Ignorable in a gate (``check --allow-todo``).
* ``!missing`` — the analysis *was* conducted and the code or process is
  not there. This is an established non-compliance and always fails the
  gate.

Both accept an optional note (``retention: !missing "no purge task, see
FAH-210"``). The loader turns the tags into :class:`Todo` / :class:`Missing`
instances, the schemas accept a :class:`Marker` wherever a human value is
expected, and ``check`` lists each occurrence in the matching section.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

import yaml
from pydantic import BaseModel, GetCoreSchemaHandler
from pydantic_core import core_schema

if TYPE_CHECKING:
    from collections.abc import Iterator

TODO_TAG = "!todo"
MISSING_TAG = "!missing"


class Marker:
    """A value deliberately left open, with an optional note.

    Pydantic validates it by instance check, so ``str | Marker`` in a
    schema means "a string, or explicitly left open" and nothing else.
    Subclasses set :attr:`tag`; instances compare by class and note so a
    bare ``!todo`` is equal to any other bare ``!todo``.
    """

    tag: ClassVar[str] = ""
    __slots__ = ("note",)

    def __init__(self, note: str | None = None) -> None:
        self.note = note or None

    def __repr__(self) -> str:
        return self.tag if self.note is None else f'{self.tag} "{self.note}"'

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, Marker)
            and type(other) is type(self)
            and other.note == self.note
        )

    def __hash__(self) -> int:
        return hash((type(self), self.note))

    @classmethod
    def __get_pydantic_core_schema__(
        cls, _source: Any, _handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        """Accept any instance of the annotated marker class."""
        return core_schema.is_instance_schema(cls)


class Todo(Marker):
    """The analysis is still owed: nobody looked yet."""

    tag = TODO_TAG
    __slots__ = ()


class Missing(Marker):
    """The analysis was done and what compliance requires is not there."""

    tag = MISSING_TAG
    __slots__ = ()


TODO = Todo()
"""The bare ``!todo`` (no note); handy for scaffolds and tests."""

MISSING = Missing()
"""The bare ``!missing``."""


class _Loader(yaml.SafeLoader):
    """SafeLoader that understands ``!todo`` and ``!missing``."""


def _construct_marker(cls: type[Marker]) -> Any:
    def construct(loader: yaml.Loader, node: yaml.Node) -> Marker:
        if not isinstance(node, yaml.ScalarNode):
            msg = f"{cls.tag} takes at most a note, not a collection"
            raise yaml.constructor.ConstructorError(None, None, msg, node.start_mark)
        return cls(str(loader.construct_scalar(node)))

    return construct


_Loader.add_constructor(TODO_TAG, _construct_marker(Todo))
_Loader.add_constructor(MISSING_TAG, _construct_marker(Missing))


class _Dumper(yaml.SafeDumper):
    """SafeDumper that writes markers back as their tag (+ note)."""


def _represent_marker(dumper: yaml.SafeDumper, data: Marker) -> yaml.Node:
    return dumper.represent_scalar(data.tag, data.note or "")


_Dumper.add_multi_representer(Marker, _represent_marker)


def load_yaml(path: Path) -> Any:
    """Parse ``path`` with marker support; ``None`` for an empty file."""
    return yaml.load(path.read_text(encoding="utf-8"), Loader=_Loader)  # noqa: S506 - SafeLoader subclass


def dump_yaml(data: Any) -> str:
    """Serialise ``data`` for a compliance file (block style, key order kept)."""
    return yaml.dump(
        data,
        Dumper=_Dumper,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
    )


def todo_text() -> str:
    """The literal a scaffold writes for a todo value."""
    return TODO_TAG


def iter_todo_paths(model: BaseModel, prefix: str = "") -> Iterator[str]:
    """Yield the dotted path of every :class:`Todo` inside a validated model."""
    for path, marker in iter_markers(model, prefix):
        if isinstance(marker, Todo):
            yield path


def iter_markers(model: BaseModel, prefix: str = "") -> Iterator[tuple[str, Marker]]:
    """Yield ``(dotted path, marker)`` for every marker inside a validated model.

    Walks nested models and lists; ``prefix`` is used for recursion.
    """
    for name in type(model).model_fields:
        value = getattr(model, name)
        path = f"{prefix}{name}"
        yield from _walk(value, path)


def field_description(model: BaseModel, dotted: str) -> str | None:
    """The schema ``description`` of the field at ``dotted``, if any.

    ``dotted`` is a path as yielded by :func:`iter_markers`
    (``dpo.email``, ``many[1].x``); list indices are skipped since the
    description lives on the field, not the element.
    """
    current: Any = model
    parts = dotted.split(".")
    for depth, part in enumerate(parts):
        if not isinstance(current, BaseModel):
            return None
        name, _, index = part.partition("[")
        info = type(current).model_fields.get(name)
        if info is None:
            return None
        if depth == len(parts) - 1:
            return info.description
        current = getattr(current, name)
        if index:
            current = current[int(index.rstrip("]"))]
    return None


def _walk(value: Any, path: str) -> Iterator[tuple[str, Marker]]:
    if isinstance(value, Marker):
        yield path, value
    elif isinstance(value, BaseModel):
        yield from iter_markers(value, f"{path}.")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk(item, f"{path}[{index}]")


__all__ = [
    "MISSING",
    "MISSING_TAG",
    "TODO",
    "TODO_TAG",
    "Marker",
    "Missing",
    "Path",
    "Todo",
    "dump_yaml",
    "field_description",
    "iter_markers",
    "iter_todo_paths",
    "load_yaml",
    "todo_text",
]
