"""Repo root, manifest selection, and manifest parsing."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from conftest import SNOW_FRONT_UNDECLARED, SNOW_TWO_UNITS
from model_wtf.compliance.discovery import (
    find_repo_root,
    load_units,
    normalise_folder,
    select_manifest,
)
from model_wtf.compliance.report import DeclarationError, Severity

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import MakeRepo

# ---------------------------------------------------------------------------
# find_repo_root
# ---------------------------------------------------------------------------


def test_find_repo_root_walks_up_to_git_dir(make_repo: MakeRepo) -> None:
    root = make_repo(dirs=("front/src/deep",))

    assert find_repo_root(root / "front" / "src" / "deep") == root.resolve()


def test_find_repo_root_accepts_git_file(tmp_path: Path) -> None:
    root = tmp_path / "worktree"
    (root / "sub").mkdir(parents=True)
    (root / ".git").write_text("gitdir: /elsewhere\n", encoding="utf-8")

    assert find_repo_root(root / "sub") == root.resolve()


def test_find_repo_root_without_git_returns_start(tmp_path: Path) -> None:
    start = tmp_path / "exported" / "tree"
    start.mkdir(parents=True)

    assert find_repo_root(start) == start.resolve()


# ---------------------------------------------------------------------------
# select_manifest
# ---------------------------------------------------------------------------


def test_select_manifest_prefers_snow_when_both_exist(make_repo: MakeRepo) -> None:
    root = make_repo(snow="images: []\n", model_wtf="units: []\n")

    assert select_manifest(root) == root / "snow.yml"


def test_select_manifest_falls_back_to_model_wtf(make_repo: MakeRepo) -> None:
    root = make_repo(model_wtf="units: []\n")

    assert select_manifest(root) == root / ".model-wtf.yml"


def test_select_manifest_missing_raises(make_repo: MakeRepo) -> None:
    root = make_repo()

    with pytest.raises(DeclarationError, match=r"No snow\.yml") as info:
        select_manifest(root)

    assert info.value.diagnostic.code == "manifest-missing"
    assert info.value.diagnostic.severity is Severity.ERROR
    assert info.value.diagnostic.path == root


# ---------------------------------------------------------------------------
# load_units: happy paths
# ---------------------------------------------------------------------------


def test_load_units_from_snow_in_manifest_order(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_TWO_UNITS)

    units, diagnostics = load_units(root / "snow.yml", root, strict=False)

    assert diagnostics == []
    assert [u.id for u in units] == ["api", "front"]
    assert [u.folder for u in units] == [
        (root / "api" / "compliance").resolve(),
        (root / "front" / "compliance").resolve(),
    ]


def test_load_units_from_model_wtf_reads_units_key(make_repo: MakeRepo) -> None:
    text = """
units:
  - id: worker
    compliance: docs/compliance
"""
    root = make_repo(model_wtf=text)

    units, diagnostics = load_units(root / ".model-wtf.yml", root, strict=False)

    assert diagnostics == []
    assert [u.id for u in units] == ["worker"]
    # ``context`` omitted defaults to ".", so the folder hangs off the root.
    assert units[0].folder == (root / "docs" / "compliance").resolve()


@pytest.mark.parametrize(
    "text",
    ["", "# only a comment\n", "images:\n"],
    ids=["empty", "comment", "images-null"],
)
def test_load_units_empty_document_yields_no_units(
    make_repo: MakeRepo, text: str
) -> None:
    root = make_repo(snow=text)

    units, diagnostics = load_units(root / "snow.yml", root, strict=False)

    assert units == []
    assert diagnostics == []


# ---------------------------------------------------------------------------
# load_units: image without compliance
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("strict", "severity"),
    [(False, Severity.WARNING), (True, Severity.ERROR)],
    ids=["lenient", "strict"],
)
def test_load_units_undeclared_image_is_diagnosed_not_a_unit(
    make_repo: MakeRepo, *, strict: bool, severity: Severity
) -> None:
    root = make_repo(snow=SNOW_FRONT_UNDECLARED)

    units, diagnostics = load_units(root / "snow.yml", root, strict=strict)

    assert [u.id for u in units] == ["api"]
    assert len(diagnostics) == 1
    diag = diagnostics[0]
    assert diag.code == "unit-no-compliance"
    assert diag.severity is severity
    assert diag.scope_id == "front"
    assert diag.path == root / "snow.yml"


# ---------------------------------------------------------------------------
# load_units: malformed manifests
# ---------------------------------------------------------------------------

DUPLICATE_IDS = """
images:
  - id: api
    compliance: compliance
  - id: api
    compliance: other
"""


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        pytest.param(DUPLICATE_IDS, "duplicate id 'api'", id="duplicate-id"),
        pytest.param(
            "images: [unterminated\n", "Cannot read snow.yml", id="yaml-syntax"
        ),
        pytest.param(
            "- just\n- a list\n", "Invalid snow.yml", id="top-level-not-mapping"
        ),
        pytest.param("images: api\n", "images", id="images-not-list"),
        pytest.param(
            "images:\n  - compliance: compliance\n", "images.0.id", id="id-missing"
        ),
        pytest.param(
            "images:\n  - id: ''\n    compliance: x\n", "images.0.id", id="id-empty"
        ),
        pytest.param(
            "images:\n  - id: api\n    compliance: [a]\n",
            "images.0.compliance",
            id="compliance-not-str",
        ),
        pytest.param(
            "images:\n  - id: api\n    context: 3\n    compliance: x\n",
            "images.0.context",
            id="context-not-str",
        ),
    ],
)
def test_load_units_malformed_manifest(
    make_repo: MakeRepo, text: str, fragment: str
) -> None:
    root = make_repo(snow=text)

    with pytest.raises(DeclarationError) as info:
        load_units(root / "snow.yml", root, strict=False)

    diag = info.value.diagnostic
    assert diag.code == "malformed-manifest"
    assert diag.severity is Severity.ERROR
    assert diag.path == root / "snow.yml"
    assert fragment in diag.message


# ---------------------------------------------------------------------------
# normalise_folder
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("context", "compliance", "expected"),
    [
        pytest.param(".", "compliance", ("compliance",), id="dot-context"),
        pytest.param("front", "compliance", ("front", "compliance"), id="nested"),
        pytest.param(
            "front/../api", "compliance", ("api", "compliance"), id="dotdot-collapsed"
        ),
        pytest.param(
            "./front", "./compliance", ("front", "compliance"), id="dot-prefixes"
        ),
    ],
)
def test_normalise_folder(
    tmp_path: Path, context: str, compliance: str, expected: tuple[str, ...]
) -> None:
    root = tmp_path.resolve()

    assert normalise_folder(root, context, compliance) == root.joinpath(*expected)
