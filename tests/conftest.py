"""Shared fixtures: a fake repository builder and a CLI invoker."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

import pytest
from click.testing import CliRunner

from model_wtf.cli import cli

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from click.testing import Result

# Two units, both declaring a compliance folder. The canonical "clean" repo.
SNOW_TWO_UNITS = """
images:
  - id: api
    context: api
    compliance: compliance
  - id: front
    context: front
    compliance: compliance
"""

# ``front`` ships without a compliance declaration.
SNOW_FRONT_UNDECLARED = """
images:
  - id: api
    context: api
    compliance: compliance
  - id: front
    context: front
"""

APP_OK = """
name: Kerfufoo
description: Back-office for the Kerfufoo client portal.
controller: acme
processor: with-madrid
"""

PARTY_ACME = """
name: ACME Corp
country: FR
address: 1 rue de la Paix, Paris
email: privacy@acme.example
"""

PARTY_WITH = """
name: WITH Madrid SL
country: ES
address: Calle Mayor 1, Madrid
email: dpo@with-madrid.com
dpo:
  name: Jane Doe
  email: dpo@with-madrid.com
"""

# Files that make every scope of ``SNOW_TWO_UNITS`` status ``ok`` and the
# declarations fully valid and filled.
FILES_ALL_OK: dict[str, str] = {
    "compliance/app.yaml": APP_OK,
    "compliance/parties/acme.yaml": PARTY_ACME,
    "compliance/parties/with-madrid.yaml": PARTY_WITH,
    "api/compliance/dpa.md": "dpa",
    "front/compliance/cookies.md": "cookies",
}


class MakeRepo(Protocol):
    """Signature of the :func:`make_repo` factory."""

    def __call__(
        self,
        *,
        snow: str | None = None,
        model_wtf: str | None = None,
        files: Mapping[str, str] | None = None,
        dirs: tuple[str, ...] = (),
        git: bool = True,
    ) -> Path: ...


@pytest.fixture
def make_repo(tmp_path: Path) -> MakeRepo:
    """Build a fake repository under ``tmp_path`` and return its root.

    ``files`` maps repo-relative paths to contents (parents are created);
    ``dirs`` lists repo-relative folders to create empty.
    """

    def _make(
        *,
        snow: str | None = None,
        model_wtf: str | None = None,
        files: Mapping[str, str] | None = None,
        dirs: tuple[str, ...] = (),
        git: bool = True,
    ) -> Path:
        root = tmp_path / "repo"
        root.mkdir(exist_ok=True)
        if git:
            (root / ".git").mkdir(exist_ok=True)
        if snow is not None:
            (root / "snow.yml").write_text(snow, encoding="utf-8")
        if model_wtf is not None:
            (root / ".model-wtf.yml").write_text(model_wtf, encoding="utf-8")
        for rel in dirs:
            (root / rel).mkdir(parents=True, exist_ok=True)
        for rel, content in (files or {}).items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return root

    return _make


class Invoke(Protocol):
    """Signature of the :func:`invoke` helper."""

    def __call__(self, *args: str) -> Result: ...


@pytest.fixture
def invoke() -> Invoke:
    """Run ``model-wtf compliance check`` with extra ``args`` via CliRunner."""
    runner = CliRunner()

    def _invoke(*args: str) -> Result:
        return runner.invoke(cli, ["compliance", "check", *args])

    return _invoke
