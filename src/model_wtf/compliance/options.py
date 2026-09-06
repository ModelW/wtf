"""Click options shared by every ``compliance`` subcommand."""

from __future__ import annotations

from pathlib import Path

import rich_click as click

from model_wtf.compliance.discovery import find_repo_root


def _inherit_root(
    ctx: click.Context, _param: click.Parameter, value: Path | None
) -> Path | None:
    """Fall back to the ``--root`` given on the top-level ``model-wtf`` group."""
    if value is not None:
        return value
    top = ctx.find_root().obj or {}
    return top.get("root")


ROOT_OPTION = click.option(
    "--root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    callback=_inherit_root,
    help=(
        "Repository root. Defaults to the top-level --root, else the enclosing "
        "Git checkout, else the cwd."
    ),
)


def resolve_root(root: Path | None) -> Path:
    """Absolute repository root from the option value or the cwd."""
    return root.resolve() if root else find_repo_root(Path.cwd())
