"""``run_check`` → ``Report``: the logic layer, no rendering."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from conftest import (
    APP_OK,
    SNOW_FRONT_UNDECLARED,
    SNOW_TWO_UNITS,
    seed_all_ok,
    seed_app,
)
from model_wtf.compliance.check import run_check
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.report import (
    Diagnostic,
    Report,
    Scope,
    ScopeKind,
    ScopeStatus,
    Severity,
)
from model_wtf.compliance.yaml_io import TODO

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import MakeRepo

CODE_DIRS = ("api", "front")


def _codes(report: Report) -> list[str]:
    return [d.code for d in report.diagnostics]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_full_repo_is_clean(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)

    report = run_check(strict=True)

    assert report.exit_code is ExitCode.CLEAN
    assert report.manifest == (root / "snow.yml").resolve()
    assert report.diagnostics == ()
    assert [(s.id, s.kind) for s in report.scopes] == [
        ("shared", ScopeKind.SHARED),
        ("api", ScopeKind.UNIT),
        ("front", ScopeKind.UNIT),
    ]
    assert all(s.status is ScopeStatus.OK for s in report.scopes)
    # The shared scope has no inventory; the units have none either (no
    # Django) but still report an item count.
    assert [s.items for s in report.scopes] == [None, 0, 0]
    assert report.scopes[0].path == (root / "compliance.db").resolve()
    assert report.scopes[2].path == (root / "front").resolve()
    assert (root / "compliance.db").is_file()
    # No YAML folder anywhere: the database is the only declared state.
    assert not (root / "compliance").exists()


# ---------------------------------------------------------------------------
# Missing pieces
# ---------------------------------------------------------------------------


def test_uninitialised_database_and_missing_code_are_errors(
    make_repo: MakeRepo,
) -> None:
    # shared: no app row (init never ran); api: code present; front: no code.
    make_repo(snow=SNOW_TWO_UNITS, dirs=("api",))

    report = run_check(strict=False)

    assert report.exit_code is ExitCode.DECLARATION_ERROR
    assert _codes(report) == ["app-missing", "code-missing"]
    assert report.diagnostics[1].scope_id == "front"
    assert [s.status for s in report.scopes] == [
        ScopeStatus.ERROR,  # app missing
        ScopeStatus.OK,
        ScopeStatus.ERROR,  # code folder missing
    ]
    assert [s.exists for s in report.scopes] == [False, True, False]


def test_scope_status_reflects_todos_and_pending(make_repo: MakeRepo) -> None:
    make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)
    seed_app(**{**APP_OK, "description": TODO})

    report = run_check(strict=False)

    assert report.exit_code is ExitCode.FINDINGS
    shared = report.scopes[0]
    assert (shared.status, shared.todos, shared.errors) == (ScopeStatus.PENDING, 1, 0)


# ---------------------------------------------------------------------------
# Unit without compliance
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("strict", "exit_code"),
    [(False, ExitCode.CLEAN), (True, ExitCode.DECLARATION_ERROR)],
    ids=["lenient", "strict"],
)
def test_undeclared_unit_is_excluded_from_scopes(
    make_repo: MakeRepo, *, strict: bool, exit_code: ExitCode
) -> None:
    make_repo(snow=SNOW_FRONT_UNDECLARED, dirs=CODE_DIRS, seed=True)

    report = run_check(strict=strict)

    assert report.exit_code is exit_code
    assert _codes(report) == ["unit-no-compliance"]
    assert report.diagnostics[0].scope_id == "front"
    assert [s.id for s in report.scopes] == ["shared", "api"]


# ---------------------------------------------------------------------------
# Declaration failures never raise
# ---------------------------------------------------------------------------


def test_missing_manifest_becomes_report(make_repo: MakeRepo) -> None:
    make_repo(dirs=CODE_DIRS)
    seed_all_ok()

    report = run_check(strict=False)

    assert report.exit_code is ExitCode.DECLARATION_ERROR
    assert report.manifest is None
    assert report.scopes == ()
    assert _codes(report) == ["manifest-missing"]


DUPLICATE_IDS = """
images:
  - id: api
    compliance:
      discover: none
  - id: api
    compliance:
      discover: none
"""


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        pytest.param("images: [broken\n", "Cannot read snow.yml", id="yaml-syntax"),
        pytest.param(DUPLICATE_IDS, "duplicate id 'api'", id="duplicate-id"),
    ],
)
def test_malformed_manifest_becomes_report(
    make_repo: MakeRepo, text: str, fragment: str
) -> None:
    make_repo(snow=text, dirs=CODE_DIRS, seed=True)

    report = run_check(strict=False)

    assert report.exit_code is ExitCode.DECLARATION_ERROR
    assert report.manifest is None
    assert report.scopes == ()
    assert _codes(report) == ["malformed-manifest"]
    assert fragment in report.diagnostics[0].message


# ---------------------------------------------------------------------------
# Report serialisation
# ---------------------------------------------------------------------------


def test_to_dict_uses_root_relative_paths(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)

    data = run_check(strict=False).to_dict()

    assert set(data) == {
        "root",
        "manifest",
        "scopes",
        "diagnostics",
        "sections",
        "exit_code",
    }
    assert data["root"] == str(root.resolve())
    assert data["manifest"] == "snow.yml"
    assert data["exit_code"] == 0
    assert [s["path"] for s in data["scopes"]] == ["compliance.db", "api", "front"]
    assert data["scopes"][0] == {
        "id": "shared",
        "kind": "shared",
        "path": "compliance.db",
        "exists": True,
        "items": None,
        "errors": 0,
        "missing": 0,
        "todos": 0,
        "pending": 0,
        "status": "ok",
    }


def test_display_path_falls_back_to_absolute_outside_root(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    outside = tmp_path / "elsewhere" / "code"
    report = Report(
        root=root,
        manifest=None,
        scopes=(Scope("x", ScopeKind.UNIT, outside, exists=False),),
        diagnostics=(Diagnostic(Severity.WARNING, "c", "m", path=root),),
    )

    data = report.to_dict()

    assert report.display_path(root) == "."
    assert data["scopes"][0]["path"] == str(outside)
    assert data["diagnostics"][0] == {
        "severity": "warning",
        "section": "info",
        "code": "c",
        "message": "m",
        "scope": None,
        "path": ".",
        "subject": None,
        "hint": None,
        "note": None,
        "origin": None,
        "items": [],
        "risk": None,
    }
