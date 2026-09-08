"""Command-line entry point for model-wtf."""

from __future__ import annotations

from pathlib import Path

import rich_click as click

from model_wtf.compliance.cli import compliance


@click.group()
@click.version_option(package_name="model-wtf", prog_name="model-wtf")
@click.option(
    "--root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help=(
        "Repository root, for every subcommand. Defaults to the enclosing Git "
        "checkout, else the cwd."
    ),
)
@click.pass_context
def cli(ctx: click.Context, *, root: Path | None) -> None:
    """Model W Transformation Facilitator."""
    ctx.obj = {"root": root}


cli.add_command(compliance)
