"""YAML in/out for compliance files, including the ``!open`` blank marker.

A human blank is not a string that happens to say "open": it is a value a
person still has to provide. It is written as the YAML tag ``!open`` (with
no content, or a hint: ``!open "ask legal"``) and loaded as an
:class:`Open` sentinel. Schemas accept the sentinel where a value is
required so the tree stays valid from ``init`` onwards; ``check`` reports
every sentinel as a warning; gates treat it as absent.

All compliance YAML goes through :func:`load` / :func:`dump` so the tag is
understood everywhere and never leaks as a plain string.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import yaml

from model_wtf.compliance.declarations.yaml_lines import (
    LineDict,
    LineList,
    LineLoader,
    load_yaml,
)

OPEN_TAG = "!open"


@dataclass(frozen=True, slots=True)
class Open:
    """A value a human still has to provide.

    Parameters
    ----------
    hint
        Optional note left by whoever created the blank ("ask the DPO").
    """

    hint: str | None = None

    def __bool__(self) -> bool:
        """A blank is falsy: ``if activity.dpia_reference`` reads naturally."""
        return False

    def __str__(self) -> str:
        return f"<open{': ' + self.hint if self.hint else ''}>"


def _construct_open(loader: yaml.SafeLoader, node: yaml.Node) -> Open:
    if isinstance(node, yaml.ScalarNode):
        value = str(loader.construct_scalar(node)).strip()
        return Open(value if value not in ("", "~", "null") else None)
    return Open()


def _represent_open(dumper: yaml.SafeDumper, data: Open) -> yaml.Node:
    # PyYAML quotes an empty scalar (``!open ''``); ``~`` is the shortest
    # explicit "nothing here" that keeps the tag readable: ``!open ~``.
    return dumper.represent_scalar(OPEN_TAG, data.hint or "~", style=None)


class Loader(LineLoader):
    """Line-tracking safe loader that understands ``!open``."""


class PlainLoader(yaml.SafeLoader):
    """Plain safe loader that understands ``!open`` (no line marks)."""


class Dumper(yaml.SafeDumper):
    """Safe dumper that writes :class:`Open` as ``!open``."""


for cls in (Loader, PlainLoader):
    cls.add_constructor(OPEN_TAG, _construct_open)
Dumper.add_representer(Open, _represent_open)


def load(text: str) -> Any:
    """Parse compliance YAML with line marks and the ``!open`` tag."""
    return yaml.load(text, Loader=Loader)  # noqa: S506 - SafeLoader subclass


def load_plain(text: str) -> Any:
    """Parse compliance YAML without line marks (``yaml.safe_load`` + ``!open``)."""
    return yaml.load(text, Loader=PlainLoader)  # noqa: S506 - SafeLoader subclass


def dump(data: Any, **kwargs: Any) -> str:
    """Serialise compliance YAML; :class:`Open` becomes ``!open``."""
    kwargs.setdefault("allow_unicode", True)
    kwargs.setdefault("sort_keys", False)
    text = str(yaml.dump(data, Dumper=Dumper, **kwargs))
    # PyYAML always quotes a tagged scalar; a bare blank reads better as
    # just the tag (``time_limit: !open``), which loads identically.
    return text.replace(f"{OPEN_TAG} '~'", OPEN_TAG)


def is_open(value: object) -> bool:
    """Whether ``value`` is a blank (an :class:`Open` sentinel)."""
    return isinstance(value, Open)


def filled[T](value: T | Open | None) -> T | None:
    """``value`` unless it is a blank; readers treat ``!open`` as absent."""
    return None if value is None or isinstance(value, Open) else value


def filled_list[T](value: list[T] | Open | None) -> list[T]:
    """A list-valued field, empty when blank or missing."""
    return [] if value is None or isinstance(value, Open) else value


__all__ = [
    "OPEN_TAG",
    "Dumper",
    "LineDict",
    "LineList",
    "Loader",
    "Open",
    "dump",
    "filled",
    "filled_list",
    "is_open",
    "load",
    "load_plain",
    "load_yaml",
]
