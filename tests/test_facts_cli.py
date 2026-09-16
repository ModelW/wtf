"""``app set`` / ``activities set``: answering the ``!todo`` questions of the
product row and of an activity from the command line."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from conftest import SNOW_TWO_UNITS, seed_activity
from model_wtf.cli import cli
from model_wtf.compliance.activities import declared_activities, update_activity
from model_wtf.compliance.declarations import load_declarations, update_app
from model_wtf.compliance.yaml_io import Marker

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import MakeRepo


@pytest.fixture
def repo(make_repo: MakeRepo) -> Path:
    root = make_repo(snow=SNOW_TWO_UNITS, dirs=("api", "front"), seed=True)
    seed_activity(
        "ordering",
        name="Ordering",
        purpose="Take and deliver orders",
        legal_basis="contract",
        data_subjects=["customers"],
        touchpoints=[],
    )
    return root


def _run(root: Path, *args: str) -> str:
    result = CliRunner().invoke(
        cli, ["compliance", *args, "--root", str(root)], env={"COLUMNS": "200"}
    )
    assert result.exit_code == 0, result.output
    return result.output


def _fail(root: Path, *args: str) -> str:
    result = CliRunner().invoke(cli, ["compliance", *args, "--root", str(root)])
    assert result.exit_code != 0, result.output
    return result.output


def test_app_show_and_set(repo: Path) -> None:
    shown = json.loads(_run(repo, "app", "show", "--format", "json"))
    assert shown["name"] == "Kerfufoo"
    assert "large_scale" not in shown

    out = _run(
        repo,
        "app",
        "set",
        "--description",
        "Food delivery for the Antilles.",
        "--large-scale",
    )
    assert "set  app: description, large_scale" in out
    app = load_declarations().app
    assert app is not None
    assert app.description == "Food delivery for the Antilles."
    assert app.large_scale is True

    _run(repo, "app", "set", "--no-large-scale", "--todo", "description")
    app = load_declarations().app
    assert app is not None
    assert app.large_scale is False
    assert isinstance(app.description, Marker)

    _run(repo, "app", "set", "--clear", "large_scale")
    shown = json.loads(_run(repo, "app", "show", "--format", "json"))
    assert "large_scale" not in shown
    assert shown["description"] == "!todo"

    assert "nothing to change" in _fail(repo, "app", "set")
    assert "controller" in _fail(repo, "app", "set", "--controller", "Not A Slug")
    with pytest.raises(ValueError, match="unknown app fields"):
        update_app(colour="blue")


def test_activities_set(repo: Path) -> None:
    out = _run(
        repo,
        "activities",
        "set",
        "ordering",
        "--retention",
        "3 years after the last order",
        "--subject",
        "customers",
        "--subject",
        "restaurants",
        "--recipient",
        "acme",
    )
    assert "set  activities/ordering: data_subjects, recipients, retention" in out
    raw = declared_activities()["ordering"]
    assert raw["retention"] == "3 years after the last order"
    assert raw["data_subjects"] == ["customers", "restaurants"]
    assert raw["recipients"] == ["acme"]

    _run(
        repo,
        "activities",
        "set",
        "ordering",
        "--legal-basis",
        "consent",
        "--consent-record",
        "people.Consent rows",
        "--todo",
        "purpose",
    )
    raw = declared_activities()["ordering"]
    assert raw["legal_basis"] == "consent"
    assert raw["consent"] == {"record": "people.Consent rows"}
    assert isinstance(raw["purpose"], Marker)

    _run(repo, "activities", "set", "ordering", "--clear", "retention")
    assert "retention" not in declared_activities()["ordering"]

    assert "no activity" in _fail(repo, "activities", "set", "nope", "--name", "x")
    assert "nothing to change" in _fail(repo, "activities", "set", "ordering")
    assert "legal-basis" in _fail(
        repo, "activities", "set", "ordering", "--legal-basis", "vibes"
    )
    with pytest.raises(ValueError, match="unknown activity fields"):
        update_activity("ordering", colour="blue")
    with pytest.raises(KeyError):
        update_activity("nope", name="x")
