"""Human blanks: declaration fields still holding the ``open`` placeholder.

``init`` scaffolds ``controller.yaml`` and ``security.yaml`` with ``open``
so the tree validates from day one; those markers must not survive to
production. ``check`` reports each one (a warning: the schema is valid, a
human just has not finished) at its line, and the GitHub renderer turns
them into ``::warning`` annotations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import yaml

from model_wtf.compliance.declarations.yaml_lines import LineDict, LineList, load_yaml
from model_wtf.compliance.report import Diagnostic, Severity

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

OPEN = "open"
"""The placeholder ``init`` writes into required human fields."""

SCANNED = ("controller.yaml", "security.yaml")
SCANNED_DIRS = ("actors", "assumptions", "recipients", "processing", "data")


def find_blanks(folder: Path, scope_id: str) -> list[Diagnostic]:
    """One ``blank`` warning per ``open`` scalar in the human files of ``folder``."""
    if not folder.is_dir():
        return []
    paths = [folder / name for name in SCANNED if (folder / name).is_file()]
    for sub in SCANNED_DIRS:
        if (folder / sub).is_dir():
            paths.extend(
                p
                for p in sorted((folder / sub).glob("*.yaml"))
                if not p.name.endswith(".gen.yaml")
            )
    out: list[Diagnostic] = []
    for path in paths:
        try:
            data = load_yaml(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            continue  # the loader already reported it
        for key, line in _open_scalars(data, ()):
            out.append(
                Diagnostic(
                    Severity.WARNING,
                    "blank",
                    f"{path.name}: {key} is still '{OPEN}'",
                    scope_id,
                    path,
                    line,
                )
            )
    return out


def _open_scalars(
    node: Any,
    trail: tuple[str, ...],
    line: int | None = None,
) -> Iterator[tuple[str, int | None]]:
    if isinstance(node, LineDict):
        for key, value in node.items():
            yield from _open_scalars(
                value, (*trail, str(key)), node.key_lines.get(key, line)
            )
    elif isinstance(node, LineList):
        for index, value in enumerate(node):
            item_line = node.item_lines[index] if index < len(node.item_lines) else line
            yield from _open_scalars(value, (*trail, str(index)), item_line)
    elif isinstance(node, str) and node.strip() == OPEN:
        yield ".".join(trail), line
