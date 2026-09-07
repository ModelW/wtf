"""``app.yaml`` + ``parties/``: schema errors, todos, references."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import yaml
from pydantic import BaseModel

from conftest import APP_OK, FILES_ALL_OK, PARTY_ACME, PARTY_WITH, SNOW_TWO_UNITS
from model_wtf.compliance.check import run_check
from model_wtf.compliance.declarations import load_declarations
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.report import Severity
from model_wtf.compliance.schemas import App
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


# ---------------------------------------------------------------------------
# !todo loader
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


def _shared(make_repo: MakeRepo, files: dict[str, str]) -> Path:
    return make_repo(snow=SNOW_TWO_UNITS, files=files) / "compliance"


def test_valid_and_filled_declarations_have_no_diagnostics(make_repo: MakeRepo) -> None:
    decl = load_declarations(_shared(make_repo, FILES_ALL_OK))

    assert decl.diagnostics == []
    assert decl.app is not None
    assert decl.app.controller == "acme"
    assert set(decl.parties) == {"acme", "with-madrid"}
    assert decl.parties["with-madrid"].dpo is not None


def test_todos_are_warnings_with_paths(make_repo: MakeRepo) -> None:
    files = dict(FILES_ALL_OK)
    files["compliance/app.yaml"] = APP_OK.replace(
        "description: Back-office for the Kerfufoo client portal.", "description: !todo"
    )
    files["compliance/parties/acme.yaml"] = PARTY_ACME.replace(
        "address: 1 rue de la Paix, Paris", "address: !todo"
    )

    decl = load_declarations(_shared(make_repo, files))

    assert [(d.code, d.severity) for d in decl.diagnostics] == [
        ("todo", Severity.WARNING),
        ("todo", Severity.WARNING),
    ]
    assert "app.yaml: description" in decl.diagnostics[0].message
    assert "acme.yaml: address" in decl.diagnostics[1].message
    assert decl.has_todos
    assert not decl.has_errors


@pytest.mark.parametrize(
    ("party_body", "expected"),
    [
        (PARTY_ACME + "colour: blue\n", "<root>: unexpected key 'colour'"),
        (PARTY_ACME.replace("country: FR", "country: France"), "country:"),
        (PARTY_ACME.replace("email: privacy@acme.example", "email: ''"), "email:"),
        (PARTY_ACME + "dpo:\n  name: X\n", "dpo.email: Field required"),
    ],
    ids=["unknown-key", "bad-country", "empty-string", "partial-block"],
)
def test_schema_errors_point_at_the_field(
    make_repo: MakeRepo, party_body: str, expected: str
) -> None:
    files = dict(FILES_ALL_OK)
    files["compliance/parties/acme.yaml"] = party_body

    decl = load_declarations(_shared(make_repo, files))

    codes = [d.code for d in decl.diagnostics]
    assert "schema-error" in codes
    assert any(expected in d.message for d in decl.diagnostics)
    assert decl.has_errors


def test_dangling_party_reference(make_repo: MakeRepo) -> None:
    files = dict(FILES_ALL_OK)
    files["compliance/app.yaml"] = APP_OK.replace(
        "controller: acme", "controller: nobody"
    )

    decl = load_declarations(_shared(make_repo, files))

    assert [d.code for d in decl.diagnostics] == ["unknown-party"]
    assert "controller 'nobody'" in decl.diagnostics[0].message


def test_open_processor_is_not_a_dangling_reference(make_repo: MakeRepo) -> None:
    files = dict(FILES_ALL_OK)
    files["compliance/app.yaml"] = APP_OK.replace(
        "processor: with-madrid", "processor: !todo"
    )

    decl = load_declarations(_shared(make_repo, files))

    assert [d.code for d in decl.diagnostics] == ["todo"]


def test_invalid_party_file_name(make_repo: MakeRepo) -> None:
    files = dict(FILES_ALL_OK)
    files["compliance/parties/With Madrid.yaml"] = PARTY_WITH

    decl = load_declarations(_shared(make_repo, files))

    assert [d.code for d in decl.diagnostics] == ["invalid-id"]


def test_missing_app_and_parties(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_TWO_UNITS, files={"compliance/x.md": ""})

    decl = load_declarations(root / "compliance")
    assert [d.code for d in decl.diagnostics] == ["app-missing"]

    (root / "compliance" / "app.yaml").write_text(APP_OK, encoding="utf-8")
    decl = load_declarations(root / "compliance")
    assert [d.code for d in decl.diagnostics] == [
        "parties-missing",
        "unknown-party",
        "unknown-party",
    ]


# ---------------------------------------------------------------------------
# Exit codes through run_check
# ---------------------------------------------------------------------------


def test_todo_exits_one_and_error_exits_three(make_repo: MakeRepo) -> None:
    files = dict(FILES_ALL_OK)
    files["compliance/parties/acme.yaml"] = PARTY_ACME.replace(
        "address: 1 rue de la Paix, Paris", "address: !todo"
    )
    root = make_repo(snow=SNOW_TWO_UNITS, files=files)
    assert run_check(root, strict=True).exit_code is ExitCode.FINDINGS

    (root / "compliance/parties/acme.yaml").write_text(
        PARTY_ACME + "bogus: 1\n", encoding="utf-8"
    )
    assert run_check(root, strict=True).exit_code is ExitCode.DECLARATION_ERROR
