"""YAML loading with the ``!open`` blank marker.

Compliance files are written by humans over time. A value that nobody has
filled yet is not "missing" (that would be a schema error) and not an
empty string (that would silently pass): it is *open*, spelled ``!open``
in YAML. The loader turns that tag into the :data:`OPEN` sentinel, the
schemas accept it wherever a human value is expected, and ``check``
reports each occurrence as a blank so the exit code says "not done yet"
rather than "broken".
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

import yaml
from pydantic import BaseModel, GetCoreSchemaHandler
from pydantic_core import core_schema

if TYPE_CHECKING:
    from collections.abc import Iterator

OPEN_TAG = "!open"


class Open:
    """Singleton marking a value a human still has to provide.

    Pydantic validates it by identity, so ``str | Open`` in a schema means
    "a string, or explicitly left open" and nothing else.
    """

    _instance: Open | None = None

    def __new__(cls) -> Self:
        """Always return the same instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance  # type: ignore[return-value]

    def __repr__(self) -> str:
        return OPEN_TAG

    @classmethod
    def __get_pydantic_core_schema__(
        cls, _source: Any, _handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        """Accept only the sentinel instance."""
        return core_schema.is_instance_schema(cls)


OPEN = Open()


class _Loader(yaml.SafeLoader):
    """SafeLoader that understands ``!open``."""


def _construct_open(_loader: yaml.Loader, _node: yaml.Node) -> Open:
    return OPEN


_Loader.add_constructor(OPEN_TAG, _construct_open)


class _Dumper(yaml.SafeDumper):
    """SafeDumper that writes the sentinel back as ``!open``."""


def _represent_open(dumper: yaml.SafeDumper, _data: Open) -> yaml.Node:
    return dumper.represent_scalar(OPEN_TAG, "")


_Dumper.add_representer(Open, _represent_open)


def load_yaml(path: Path) -> Any:
    """Parse ``path`` with ``!open`` support; ``None`` for an empty file."""
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


def open_text() -> str:
    """The literal a scaffold writes for a blank value."""
    return OPEN_TAG


def iter_open_paths(model: BaseModel, prefix: str = "") -> Iterator[str]:
    """Yield the dotted path of every :data:`OPEN` inside a validated model.

    Walks nested models and lists; ``prefix`` is used for recursion.
    """
    for name in type(model).model_fields:
        value = getattr(model, name)
        path = f"{prefix}{name}"
        yield from _walk(value, path)


def _walk(value: Any, path: str) -> Iterator[str]:
    if isinstance(value, Open):
        yield path
    elif isinstance(value, BaseModel):
        yield from iter_open_paths(value, f"{path}.")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk(item, f"{path}[{index}]")


__all__ = [
    "OPEN",
    "OPEN_TAG",
    "Open",
    "Path",
    "dump_yaml",
    "iter_open_paths",
    "load_yaml",
    "open_text",
]
