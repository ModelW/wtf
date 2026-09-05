"""Command-line entry point for model-wtf."""

import rich_click as click


@click.group()
def cli() -> None:
    """Model W Transformation Facilitator."""
