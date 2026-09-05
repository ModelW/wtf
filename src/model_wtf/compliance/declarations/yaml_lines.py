"""A YAML loader that remembers where each node came from.

Validation errors are only actionable when they point at a line: a DPO
reviewing ``processing/billing.yaml`` should not have to guess which of
three recipients is the unknown one. PyYAML's ``safe_load`` throws that
information away, so this module keeps it on the containers it builds and
offers :func:`line_of` to translate a Pydantic error location back into a
line number.
"""

from __future__ import annotations

from typing import Any

import yaml


class LineDict(dict[Any, Any]):
    """A ``dict`` that knows the line of the mapping and of each key."""

    __slots__ = ("key_lines", "line")

    def __init__(self) -> None:
        super().__init__()
        self.line: int = 1
        self.key_lines: dict[Any, int] = {}


class LineList(list[Any]):
    """A ``list`` that knows the line of the sequence and of each item."""

    __slots__ = ("item_lines", "line")

    def __init__(self) -> None:
        super().__init__()
        self.line: int = 1
        self.item_lines: list[int] = []


class LineLoader(yaml.SafeLoader):
    """``SafeLoader`` producing :class:`LineDict` / :class:`LineList`.

    Only containers are annotated: scalars keep their native types so the
    data validates exactly as with ``safe_load``.
    """

    def construct_yaml_map(self, node: yaml.Node) -> Any:
        """Build a :class:`LineDict`, recording the line of every key."""
        data = LineDict()
        data.line = node.start_mark.line + 1
        yield data
        if isinstance(node, yaml.MappingNode):
            data.update(self.construct_mapping(node, deep=True))
            data.key_lines = {
                self.construct_object(key_node, deep=True): key_node.start_mark.line + 1
                for key_node, _ in node.value
            }

    def construct_yaml_seq(self, node: yaml.Node) -> Any:
        """Build a :class:`LineList`, recording the line of every item."""
        data = LineList()
        data.line = node.start_mark.line + 1
        yield data
        if isinstance(node, yaml.SequenceNode):
            data.extend(self.construct_sequence(node, deep=True))
            data.item_lines = [child.start_mark.line + 1 for child in node.value]


LineLoader.add_constructor("tag:yaml.org,2002:map", LineLoader.construct_yaml_map)
LineLoader.add_constructor("tag:yaml.org,2002:seq", LineLoader.construct_yaml_seq)


def load_yaml(text: str) -> Any:
    """Parse ``text`` like ``yaml.safe_load`` but with line-annotated containers.

    Raises
    ------
    yaml.YAMLError
        On syntax errors (the caller turns them into diagnostics).
    """
    return yaml.load(text, Loader=LineLoader)  # noqa: S506 - SafeLoader subclass


def line_of(data: Any, loc: tuple[int | str, ...]) -> int | None:
    """Find the line the error location ``loc`` points at inside ``data``.

    ``loc`` is a Pydantic error location: a mix of keys, indices and, for
    unions, the name of the variant tried (``('fields', 'email',
    'OpaqueField', 'contents')``). Variant names do not exist in the data,
    so unknown steps are skipped rather than aborting. A missing final key
    (``Field required``) resolves to the line of its parent mapping, which
    is where the user has to add it.
    """
    line: int | None = getattr(data, "line", None)
    current = data
    for step in loc:
        if isinstance(current, LineDict):
            if step in current:
                line = current.key_lines.get(step, line)
                current = current[step]
                continue
            return line
        if isinstance(current, LineList) and isinstance(step, int):
            if 0 <= step < len(current):
                line = current.item_lines[step]
                current = current[step]
                continue
            return line
        # Union variant name or scalar reached: nothing to descend into.
    return line
