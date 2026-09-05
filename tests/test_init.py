"""``compliance init``: scaffold, manifest wiring, CODEOWNERS, idempotency."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from model_wtf.cli import cli
from model_wtf.compliance.check import run_check
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.init import InitError, detect_units, run_init
from model_wtf.compliance.report import Severity

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import MakeRepo

SNOW_WITH_COMMENTS = """\
# Deployment manifest -- keep me
version: 2
images:
    # the Django API
    - id: api
      context: api
      dockerfile: api/Dockerfile   # trailing comment
      envs: [prod, staging]
    - id: front
      context: front
    - id: worker
      context: api
      compliance: compliance # already wired
"""


def _files(root: Path) -> set[str]:
    return {
        p.relative_to(root).as_posix()
        for p in root.rglob("*")
        if p.is_file() and ".git/" not in p.relative_to(root).as_posix()
    }


def test_snow_repo_is_scaffolded(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_WITH_COMMENTS)

    report = run_init(root, codeowners_team="@acme/dpo")

    assert report.manifest_edits == [
        "snow.yml: images[api].compliance",
        "snow.yml: images[front].compliance",
    ]
    files = _files(root)
    for unit in ("api", "front"):
        assert f"{unit}/compliance/security.yaml" in files
        assert f"{unit}/compliance/README.md" in files
        assert f"{unit}/compliance/actors/anonymous.yaml" in files
        assert f"{unit}/compliance/actors/staff.yaml" in files
        assert f"{unit}/compliance/data/.gitkeep" in files
        assert f"{unit}/compliance/elements/.gitkeep" in files
    # Several units: the controller is shared at the repo root.
    assert "compliance/controller.yaml" in files
    assert "api/compliance/controller.yaml" not in files
    assert "open" in (root / "compliance/controller.yaml").read_text()
    assert report.codeowners_lines == [
        "/api/compliance/ @acme/dpo",
        "/front/compliance/ @acme/dpo",
    ]
    assert (root / ".github/CODEOWNERS").read_text().count("@acme/dpo") == 2


def test_snow_yml_diff_is_minimal(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_WITH_COMMENTS)

    run_init(root, codeowners_team="@acme/dpo")

    after = (root / "snow.yml").read_text()
    assert "# Deployment manifest -- keep me" in after
    assert "# the Django API" in after
    assert "# trailing comment" in after
    assert "# already wired" in after
    assert after.index("id: api") < after.index("id: front") < after.index("id: worker")
    assert after.count("compliance: compliance") == 3
    # Nothing else changed: dropping the two added lines gives the original.
    added = "compliance: compliance"
    kept = [line.rstrip() for line in after.splitlines() if line.strip() != added]
    assert kept == [line.rstrip() for line in SNOW_WITH_COMMENTS.splitlines()]


def test_second_run_changes_nothing(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_WITH_COMMENTS)
    run_init(root, codeowners_team="@acme/dpo")
    (root / "api/compliance/security.yaml").write_text("general_description: mine\n")
    snapshot = {p: (root / p).read_text() for p in _files(root)}

    report = run_init(root, codeowners_team="@acme/dpo")

    assert not report.changed
    assert {p: (root / p).read_text() for p in _files(root)} == snapshot


def test_unit_filter(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_WITH_COMMENTS)

    report = run_init(root, units=["api"], codeowners_team="@acme/dpo")

    assert report.manifest_edits == ["snow.yml: images[api].compliance"]
    files = _files(root)
    assert "api/compliance/security.yaml" in files
    assert not any(f.startswith("front/") for f in files)
    # Single unit initialised: controller lives in the unit folder.
    assert "api/compliance/controller.yaml" in files
    assert "compliance/controller.yaml" not in files
    snow = (root / "snow.yml").read_text()
    assert snow.count("compliance: compliance") == 2  # api + the pre-wired worker


def test_unknown_unit_errors(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_WITH_COMMENTS)
    with pytest.raises(InitError, match="unknown unit"):
        run_init(root, units=["nope"], codeowners_team="@acme/dpo")


def test_scaffold_passes_check(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_WITH_COMMENTS)
    run_init(root, codeowners_team="@acme/dpo")

    report = run_check(root, strict=True)

    assert not any(d.severity is Severity.ERROR for d in report.diagnostics), (
        report.diagnostics
    )
    assert report.exit_code is ExitCode.CLEAN


def test_single_root_unit_shares_folder(make_repo: MakeRepo) -> None:
    root = make_repo(snow="images:\n  - id: app\n    context: .\n")

    report = run_init(root, codeowners_team="@acme/dpo")

    files = _files(root)
    assert "compliance/controller.yaml" in files
    assert "compliance/security.yaml" in files
    assert report.codeowners_lines == ["/compliance/ @acme/dpo"]


# ---------------------------------------------------------------------------
# No snow.yml: Dockerfiles -> .model-wtf.yml
# ---------------------------------------------------------------------------


def test_detect_units_from_dockerfiles(make_repo: MakeRepo) -> None:
    root = make_repo(
        files={
            "api/Dockerfile": "FROM python",
            "api/Dockerfile.worker": "FROM python",
            "front/Dockerfile": "FROM node",
            "node_modules/x/Dockerfile": "FROM nope",
            "front/.venv/Dockerfile": "FROM nope",
        }
    )

    plans = detect_units(root)

    assert [(p.id, p.context) for p in plans] == [
        ("api", "api"),
        ("api-worker", "api"),
        ("front", "front"),
    ]


def test_fallback_manifest_written_after_confirmation(make_repo: MakeRepo) -> None:
    root = make_repo(files={"api/Dockerfile": "FROM python", "front/Dockerfile": "x"})
    seen: list[list[str]] = []

    def confirm(detected: list[object]) -> bool:
        seen.append([p.id for p in detected])  # type: ignore[attr-defined]
        return True

    report = run_init(root, codeowners_team="@acme/dpo", confirm_units=confirm)

    assert seen == [["api", "front"]]
    manifest = (root / ".model-wtf.yml").read_text()
    assert "units:" in manifest
    assert "- id: api" in manifest
    assert "compliance: compliance" in manifest
    assert "api/compliance/security.yaml" in _files(root)
    assert any(e.startswith(".model-wtf.yml: created") for e in report.manifest_edits)
    assert run_check(root, strict=True).exit_code is ExitCode.CLEAN


def test_fallback_declined(make_repo: MakeRepo) -> None:
    root = make_repo(files={"api/Dockerfile": "FROM python"})
    with pytest.raises(InitError, match="aborted"):
        run_init(root, codeowners_team="@acme/dpo", confirm_units=lambda _: False)
    assert not (root / ".model-wtf.yml").exists()


def test_root_dockerfile_uses_repo_name(make_repo: MakeRepo) -> None:
    root = make_repo(files={"Dockerfile": "FROM python"})
    plans = detect_units(root)
    assert [(p.id, p.context) for p in plans] == [("repo", ".")]


def test_nothing_detected_warns(make_repo: MakeRepo) -> None:
    root = make_repo()
    report = run_init(root, codeowners_team="@acme/dpo")
    assert not report.changed
    assert report.warnings


# ---------------------------------------------------------------------------
# CODEOWNERS
# ---------------------------------------------------------------------------


def test_codeowners_appends_to_existing_and_skips_duplicates(
    make_repo: MakeRepo,
) -> None:
    root = make_repo(
        snow=SNOW_WITH_COMMENTS,
        files={"CODEOWNERS": "* @acme/devs\n/api/compliance/ @acme/dpo\n"},
    )

    report = run_init(root, codeowners_team="acme/dpo")

    text = (root / "CODEOWNERS").read_text()
    assert report.codeowners_lines == ["/front/compliance/ @acme/dpo"]
    assert text.startswith("* @acme/devs\n/api/compliance/ @acme/dpo\n")
    assert text.count("/api/compliance/") == 1
    assert not (root / ".github/CODEOWNERS").exists()


def test_codeowners_skipped_without_team_or_remote(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_WITH_COMMENTS)  # fake .git dir, no remote

    report = run_init(root)

    assert report.codeowners_lines == []
    assert any("CODEOWNERS skipped" in w for w in report.warnings)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_reports_and_prints_next_step(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_WITH_COMMENTS)

    result = CliRunner().invoke(
        cli,
        ["compliance", "init", "--root", str(root), "--codeowners-team", "@acme/dpo"],
    )

    assert result.exit_code == 0, result.output
    assert "images[api].compliance" in result.output
    assert "/api/compliance/ @acme/dpo" in result.output
    assert (
        "next: fill controller.yaml, then run model-wtf compliance auto"
        in result.output
    )

    again = CliRunner().invoke(cli, ["compliance", "init", "--root", str(root)])
    assert "Nothing to do" in again.output


def test_cli_yes_skips_prompt(make_repo: MakeRepo) -> None:
    root = make_repo(files={"api/Dockerfile": "FROM python"})

    result = CliRunner().invoke(
        cli,
        [
            "compliance",
            "init",
            "--root",
            str(root),
            "--yes",
            "--codeowners-team",
            "@a/dpo",
        ],
    )

    assert result.exit_code == 0, result.output
    assert (root / ".model-wtf.yml").exists()


def test_cli_prompt_declined(make_repo: MakeRepo) -> None:
    root = make_repo(files={"api/Dockerfile": "FROM python"})

    result = CliRunner().invoke(
        cli, ["compliance", "init", "--root", str(root)], input="n\n"
    )

    assert result.exit_code == 1
    assert "aborted" in result.output
