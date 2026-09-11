"""Click options shared by every ``compliance`` subcommand."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, TypeVar

import rich_click as click

from model_wtf.compliance.discovery import find_repo_root
from model_wtf.opencode import DEFAULT_MODEL, SCALEWAY_DEFAULT_MODEL, default_model

if TYPE_CHECKING:
    from collections.abc import Callable

F = TypeVar("F", bound="Callable[..., object]")


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


def _default_model(
    _ctx: click.Context, _param: click.Parameter, value: str | None
) -> str:
    """Resolve the model at call time, so the environment's key decides."""
    return value if value is not None else default_model()


def model_option(help_text: str = "provider/model.") -> Callable[[F], F]:
    """The ``--model`` option; its default follows the key in the environment.

    OpenRouter's router, or with ``SCALEWAY_SECRET_KEY`` only: the model
    the deployment at ``SCALEWAY_INFERENCE_ENDPOINT`` serves, else
    Scaleway's hosted default.
    """
    return click.option(
        "--model",
        default=None,
        callback=_default_model,
        help=(
            f"{help_text} Default: {DEFAULT_MODEL} with OPENROUTER_API_KEY; with "
            "SCALEWAY_SECRET_KEY only, scaleway-dedicated/<served model> when "
            f"SCALEWAY_INFERENCE_ENDPOINT is set, else {SCALEWAY_DEFAULT_MODEL}."
        ),
    )


def resolve_root(root: Path | None) -> Path:
    """Absolute repository root from the option value or the cwd."""
    return root.resolve() if root else find_repo_root(Path.cwd())
