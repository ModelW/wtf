"""The app and the parties: schema errors, todos, references."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import yaml
from pydantic import BaseModel

from conftest import (
    APP_OK,
    PARTY_ACME,
    PARTY_WITH,
    SNOW_TWO_UNITS,
    seed_all_ok,
    seed_app,
    seed_party,
)
from model_wtf.compliance.check import run_check
from model_wtf.compliance.declarations import load_declarations, save_party
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.report import Severity
from model_wtf.compliance.schemas import App
from model_wtf.compliance.tables import decode_human, encode_human
from model_wtf.compliance.yaml_io import (
    TODO,
    Marker,
    Missing,
    Todo,
    dump_yaml,
    iter_markers,
    iter_todo_paths,
    load_yaml,
)

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import MakeRepo

CODE_DIRS = ("api", "front")


# ---------------------------------------------------------------------------
# !todo loader (the knowledge files are still YAML)
# ---------------------------------------------------------------------------


def test_markers_load_with_optional_notes(tmp_path: Path) -> None:
    path = tmp_path / "f.yaml"
    path.write_text(
        'a: !todo\nb:\n  - !todo "ask legal"\n  - 1\nc: !missing "no purge task"\n',
        encoding="utf-8",
    )

    data = load_yaml(path)

    assert data["a"] == TODO
    assert data["a"].note is None
    assert data["b"][0] == Todo("ask legal")
    assert data["b"][0] != TODO
    assert data["c"] == Missing("no purge task")
    assert not isinstance(data["c"], Todo)
    assert isinstance(data["c"], Marker)
    assert repr(data["c"]) == '!missing "no purge task"'


def test_marker_collections_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "f.yaml"
    path.write_text("a: !todo [1, 2]\n", encoding="utf-8")

    with pytest.raises(yaml.YAMLError, match="at most a note"):
        load_yaml(path)


def test_open_round_trips_through_dump() -> None:
    assert dump_yaml({"a": TODO, "b": "x"}) == "a: !todo ''\nb: x\n"
    assert dump_yaml({"a": Missing("why")}) == "a: !missing 'why'\n"


def test_markers_round_trip_through_the_database_codec() -> None:
    """The ``Human`` column stores markers as one-key objects, recursively."""
    value = {"a": TODO, "b": [Missing("why"), "x"], "c": {"d": Todo("n")}}
    encoded = encode_human(value)
    assert encoded == {
        "a": {"todo": None},
        "b": [{"missing": "why"}, "x"],
        "c": {"d": {"todo": "n"}},
    }
    assert decode_human(encoded) == value
    # A one-key mapping that is not a marker stays a mapping.
    assert decode_human({"exempt": "derived"}) == {"exempt": "derived"}


def test_iter_todo_paths_walks_nested_models() -> None:
    class Inner(BaseModel):
        x: str | Marker

    class Outer(BaseModel):
        a: str | Marker
        inner: Inner
        many: list[Inner]

    model = Outer(
        a=TODO, inner=Inner(x=Missing("gone")), many=[Inner(x="ok"), Inner(x=TODO)]
    )

    assert list(iter_todo_paths(model)) == ["a", "many[1].x"]
    assert list(iter_markers(model)) == [
        ("a", TODO),
        ("inner.x", Missing("gone")),
        ("many[1].x", TODO),
    ]


def test_open_is_rejected_where_not_allowed() -> None:
    # ``processor`` may be open; a boolean-ish field like ``name`` may too,
    # but a non-``Todo`` unknown object must fail.
    with pytest.raises(ValueError, match="controller"):
        App.model_validate({"name": "x", "description": "y", "controller": object()})


# ---------------------------------------------------------------------------
# Declarations
# ---------------------------------------------------------------------------


def test_valid_and_filled_declarations_have_no_diagnostics(make_repo: MakeRepo) -> None:
    make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)

    decl = load_declarations()

    assert decl.diagnostics == []
    assert decl.app is not None
    assert decl.app.controller == "acme"
    assert set(decl.parties) == {"acme", "with-madrid"}
    assert decl.parties["with-madrid"].dpo is not None


def test_todos_are_warnings_with_subjects(make_repo: MakeRepo) -> None:
    make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)
    seed_app(**{**APP_OK, "description": TODO})
    seed_party("acme", **{**PARTY_ACME, "address": TODO})

    decl = load_declarations()

    assert [(d.code, d.severity) for d in decl.diagnostics] == [
        ("todo", Severity.WARNING),
        ("todo", Severity.WARNING),
    ]
    assert "app: description" in decl.diagnostics[0].message
    assert "parties/acme: address" in decl.diagnostics[1].message
    assert decl.diagnostics[1].subject == "parties/acme#address"
    assert decl.has_todos
    assert not decl.has_errors


@pytest.mark.parametrize(
    ("party", "expected"),
    [
        ({**PARTY_ACME, "country": "France"}, "country:"),
        ({**PARTY_ACME, "email": ""}, "email:"),
        ({**PARTY_ACME, "dpo": {"name": "X"}}, "dpo.email: Field required"),
    ],
    ids=["bad-country", "empty-string", "partial-block"],
)
def test_schema_errors_point_at_the_field(
    make_repo: MakeRepo, party: dict[str, object], expected: str
) -> None:
    make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)
    seed_party("acme", **party)

    decl = load_declarations()

    codes = [d.code for d in decl.diagnostics]
    assert "schema-error" in codes
    assert any(expected in d.message for d in decl.diagnostics)
    assert decl.has_errors


def test_save_party_validates_before_writing(make_repo: MakeRepo) -> None:
    make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)
    with pytest.raises(ValueError, match="colour"):
        save_party("x", {**PARTY_ACME, "colour": "blue"})
    assert save_party("acme", PARTY_ACME) is False  # exists, untouched
    mapbox = {**PARTY_ACME, "name": "Mapbox", "hosts": ["api.mapbox.com"]}
    assert save_party("mapbox", mapbox)
    assert load_declarations().parties["mapbox"].hosts == ["api.mapbox.com"]


def test_dangling_party_reference(make_repo: MakeRepo) -> None:
    make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)
    seed_app(**{**APP_OK, "controller": "nobody"})

    decl = load_declarations()

    assert [d.code for d in decl.diagnostics] == ["unknown-party"]
    assert "controller 'nobody'" in decl.diagnostics[0].message


def test_open_processor_is_not_a_dangling_reference(make_repo: MakeRepo) -> None:
    make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)
    seed_app(**{**APP_OK, "processor": TODO})

    decl = load_declarations()

    assert [d.code for d in decl.diagnostics] == ["todo"]


def test_invalid_party_id(make_repo: MakeRepo) -> None:
    make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)
    seed_party("With Madrid", **PARTY_WITH)

    decl = load_declarations()

    assert [d.code for d in decl.diagnostics] == ["invalid-id"]


def test_missing_app_and_parties(make_repo: MakeRepo) -> None:
    make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS)

    decl = load_declarations()
    assert [d.code for d in decl.diagnostics] == ["app-missing"]

    seed_app(**APP_OK)
    decl = load_declarations()
    assert [d.code for d in decl.diagnostics] == ["unknown-party", "unknown-party"]


# ---------------------------------------------------------------------------
# Exit codes through run_check
# ---------------------------------------------------------------------------


def test_todo_exits_one_and_error_exits_three(make_repo: MakeRepo) -> None:
    make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS)
    seed_all_ok()
    seed_party("acme", **{**PARTY_ACME, "address": TODO})
    assert run_check(strict=True).exit_code is ExitCode.FINDINGS

    seed_party("acme", **{**PARTY_ACME, "country": "France"})
    assert run_check(strict=True).exit_code is ExitCode.DECLARATION_ERROR
