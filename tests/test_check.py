"""``run_check`` → ``Report``: the logic layer, no rendering."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from conftest import FILES_ALL_OK, SNOW_FRONT_UNDECLARED, SNOW_TWO_UNITS
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

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import MakeRepo


def _codes(report: Report) -> list[str]:
    return [d.code for d in report.diagnostics]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_full_repo_is_clean(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_TWO_UNITS, files=FILES_ALL_OK)

    report = run_check(root, strict=True)

    assert report.exit_code is ExitCode.CLEAN
    assert report.manifest == (root / "snow.yml").resolve()
    assert report.diagnostics == ()
    assert [(s.id, s.kind) for s in report.scopes] == [
        ("shared", ScopeKind.SHARED),
        ("api", ScopeKind.UNIT),
        ("front", ScopeKind.UNIT),
    ]
    assert all(s.status is ScopeStatus.OK for s in report.scopes)
    assert [s.file_count for s in report.scopes] == [1, 1, 1]
    assert report.scopes[2].path == (root / "front" / "compliance").resolve()


def test_file_count_is_recursive(make_repo: MakeRepo) -> None:
    root = make_repo(
        snow="images: []\n",
        files={
            "compliance/a.md": "",
            "compliance/sub/b.md": "",
            "compliance/sub/deep/c.md": "",
        },
    )

    report = run_check(root, strict=False)

    assert report.scopes[0].file_count == 3


# ---------------------------------------------------------------------------
# Nothing declared
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("strict", "severity", "exit_code"),
    [
        (False, Severity.WARNING, ExitCode.CLEAN),
        (True, Severity.ERROR, ExitCode.DECLARATION_ERROR),
    ],
    ids=["lenient", "strict"],
)
def test_nothing_declared_when_all_folders_empty_or_missing(
    make_repo: MakeRepo, *, strict: bool, severity: Severity, exit_code: ExitCode
) -> None:
    # shared: only hidden content; api: empty dir; front: missing entirely.
    root = make_repo(
        snow=SNOW_TWO_UNITS,
        files={"compliance/.gitkeep": "", "compliance/.hidden/secret.md": "x"},
        dirs=("api/compliance",),
    )

    report = run_check(root, strict=strict)

    assert report.exit_code is exit_code
    assert _codes(report) == ["nothing-declared"]
    diag = report.diagnostics[0]
    assert diag.severity is severity
    assert diag.path == root.resolve()
    assert [s.status for s in report.scopes] == [
        ScopeStatus.EMPTY,
        ScopeStatus.EMPTY,
        ScopeStatus.MISSING,
    ]
    assert [s.file_count for s in report.scopes] == [0, 0, 0]


def test_hidden_files_do_not_rescue_an_otherwise_declared_repo(
    make_repo: MakeRepo,
) -> None:
    root = make_repo(
        snow="images: []\n",
        files={"compliance/.gitkeep": "", "compliance/real.md": "x"},
    )

    report = run_check(root, strict=True)

    assert report.exit_code is ExitCode.CLEAN
    assert report.scopes[0].file_count == 1


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
    root = make_repo(snow=SNOW_FRONT_UNDECLARED, files=FILES_ALL_OK)

    report = run_check(root, strict=strict)

    assert report.exit_code is exit_code
    assert _codes(report) == ["unit-no-compliance"]
    assert report.diagnostics[0].scope_id == "front"
    assert [s.id for s in report.scopes] == ["shared", "api"]


# ---------------------------------------------------------------------------
# Declaration failures never raise
# ---------------------------------------------------------------------------


def test_missing_manifest_becomes_report(make_repo: MakeRepo) -> None:
    root = make_repo(files=FILES_ALL_OK)

    report = run_check(root, strict=False)

    assert report.exit_code is ExitCode.DECLARATION_ERROR
    assert report.manifest is None
    assert report.scopes == ()
    assert _codes(report) == ["manifest-missing"]


DUPLICATE_IDS = """
images:
  - id: api
    compliance: compliance
  - id: api
    compliance: compliance
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
    root = make_repo(snow=text, files=FILES_ALL_OK)

    report = run_check(root, strict=False)

    assert report.exit_code is ExitCode.DECLARATION_ERROR
    assert report.manifest is None
    assert report.scopes == ()
    assert _codes(report) == ["malformed-manifest"]
    assert fragment in report.diagnostics[0].message


# ---------------------------------------------------------------------------
# Report serialisation
# ---------------------------------------------------------------------------


def test_to_dict_uses_root_relative_paths(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_TWO_UNITS, files=FILES_ALL_OK)

    data = run_check(root, strict=False).to_dict()

    assert set(data) == {"root", "manifest", "scopes", "diagnostics", "exit_code"}
    assert data["root"] == str(root.resolve())
    assert data["manifest"] == "snow.yml"
    assert data["exit_code"] == 0
    assert [s["path"] for s in data["scopes"]] == [
        "compliance",
        "api/compliance",
        "front/compliance",
    ]
    assert data["scopes"][0] == {
        "id": "shared",
        "kind": "shared",
        "path": "compliance",
        "exists": True,
        "file_count": 1,
        "status": "ok",
    }


def test_display_path_falls_back_to_absolute_outside_root(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    outside = tmp_path / "elsewhere" / "compliance"
    report = Report(
        root=root,
        manifest=None,
        scopes=(Scope("x", ScopeKind.UNIT, outside, exists=False, file_count=0),),
        diagnostics=(Diagnostic(Severity.WARNING, "c", "m", path=root),),
    )

    data = report.to_dict()

    assert report.display_path(root) == "."
    assert data["scopes"][0]["path"] == str(outside)
    assert data["diagnostics"][0] == {
        "severity": "warning",
        "code": "c",
        "message": "m",
        "scope": None,
        "path": ".",
    }
