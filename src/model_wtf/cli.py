"""Command-line entry point for model-wtf."""

import rich_click as click

from model_wtf.compliance.cli import compliance
from model_wtf.knowledge.cli import rules


@click.group()
def cli() -> None:
    """Model W Transformation Facilitator."""


cli.add_command(compliance)
cli.add_command(rules)
