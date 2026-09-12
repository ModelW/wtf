"""``model-wtf compliance check`` end-to-end through CliRunner."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from conftest import (
    APP_OK,
    PARTY_ACME,
    SNOW_FRONT_UNDECLARED,
    SNOW_TWO_UNITS,
    seed_app,
    seed_party,
)
from model_wtf.cli import cli
from model_wtf.compliance.yaml_io import TODO, Missing, Todo

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import Invoke, MakeRepo

CODE_DIRS = ("api", "front")


# ---------------------------------------------------------------------------
# Happy path: text
# ---------------------------------------------------------------------------


def test_text_output_lists_all_scopes(make_repo: MakeRepo, invoke: Invoke) -> None:
    root = make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)

    result = invoke("--root", str(root))

    assert result.exit_code == 0
    assert "Compliance scopes" in result.output
    for scope_id in ("shared", "api", "front"):
        assert re.search(rf"\b{scope_id}\b", result.output)
    assert "compliance.db" in result.output
    assert "./front" not in result.output
    assert "Exit code" not in result.output


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("snow", "strict", "expected_exit"),
    [
        pytest.param(SNOW_TWO_UNITS, False, 0, id="clean"),
        pytest.param(SNOW_FRONT_UNDECLARED, True, 3, id="strict-failure"),
    ],
)
def test_json_output_is_valid_and_matches_exit_code(
    make_repo: MakeRepo, invoke: Invoke, snow: str, *, strict: bool, expected_exit: int
) -> None:
    root = make_repo(snow=snow, dirs=CODE_DIRS, seed=True)
    args = ["--root", str(root), "--format", "json"]
    if strict:
        args.append("--strict")

    result = invoke(*args)

    assert result.exit_code == expected_exit
    data = json.loads(result.stdout)
    assert set(data) == {
        "root",
        "manifest",
        "scopes",
        "diagnostics",
        "sections",
        "exit_code",
    }
    assert data["exit_code"] == expected_exit
    assert data["manifest"] == "snow.yml"


# ---------------------------------------------------------------------------
# GitHub annotations
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("extra", "severity", "expected_exit"),
    [
        # Outside --strict an image without a compliance block is advisory:
        # a notice, since there is nothing to do from a compliance standpoint.
        pytest.param((), "notice", 0, id="lenient"),
        pytest.param(("--strict",), "error", 3, id="strict"),
    ],
)
def test_github_output_emits_annotation(
    make_repo: MakeRepo,
    invoke: Invoke,
    extra: tuple[str, ...],
    severity: str,
    expected_exit: int,
) -> None:
    root = make_repo(snow=SNOW_FRONT_UNDECLARED, dirs=CODE_DIRS, seed=True)

    result = invoke("--root", str(root), "--format", "github", *extra)

    assert result.exit_code == expected_exit
    lines = result.stdout.splitlines()
    annotations = [line for line in lines if line.startswith("::")]
    assert annotations == [
        f"::{severity} file=snow.yml,title=unit-no-compliance::"
        "image 'front' declares no 'compliance' block"
    ]


# ---------------------------------------------------------------------------
# --strict flips warnings to errors
# ---------------------------------------------------------------------------


def test_strict_turns_exit_zero_into_three(make_repo: MakeRepo, invoke: Invoke) -> None:
    root = make_repo(snow=SNOW_FRONT_UNDECLARED, dirs=CODE_DIRS, seed=True)

    lenient = invoke("--root", str(root))
    strict = invoke("--root", str(root), "--strict")

    assert lenient.exit_code == 0
    assert "Info" in lenient.output
    assert strict.exit_code == 3
    assert "Errors" in strict.output
    for result in (lenient, strict):
        assert "declares no" in result.output


# ---------------------------------------------------------------------------
# The to-do list: sections, folding, --allow-todo, --todo, --verbose
# ---------------------------------------------------------------------------


def _with_open_questions() -> None:
    seed_app(**{**APP_OK, "description": TODO})
    seed_party(
        "acme",
        name="ACME Corp",
        country="FR",
        address=Todo("ask legal"),
        email=TODO,
    )


def test_todos_fold_per_record_and_allow_todo_waves_them(
    make_repo: MakeRepo, invoke: Invoke
) -> None:
    root = make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)
    _with_open_questions()

    result = invoke("--root", str(root))
    waved = invoke("--root", str(root), "--allow-todo")

    assert result.exit_code == 1
    assert "Todo" in result.output
    assert "app: description" in result.output
    # One line per record, notes kept.
    assert 'parties/acme: address "ask legal", email' in result.output
    assert "3 todo" in result.output
    assert waved.exit_code == 0
    assert "app: description" in waved.output  # still listed


def test_missing_always_fails(make_repo: MakeRepo, invoke: Invoke) -> None:
    root = make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)
    seed_party(
        "acme",
        **{**PARTY_ACME, "email": Missing("no privacy contact exists")},
    )

    result = invoke("--root", str(root), "--allow-todo")
    github = invoke("--root", str(root), "--format", "github")

    assert result.exit_code == 1
    assert "Missing" in result.output
    assert 'parties/acme: email "no privacy contact exists"' in result.output
    assert "1 missing" in result.output
    assert any(
        line.startswith("::error title=missing::parties/acme: email is !missing")
        for line in github.stdout.splitlines()
    )


def test_todo_flag_prints_the_questionnaire(
    make_repo: MakeRepo, invoke: Invoke
) -> None:
    root = make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)
    _with_open_questions()

    result = invoke("--root", str(root), "--todo")

    lines = result.output.splitlines()
    assert lines[0].startswith("app description: What the product does")
    assert "parties/acme address" in result.output
    assert "Compliance scopes" not in result.output


def test_todo_flag_on_a_clean_repo(make_repo: MakeRepo, invoke: Invoke) -> None:
    root = make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)

    result = invoke("--root", str(root), "--todo")

    assert result.output.strip() == "No open question."


def test_json_groups_by_section(make_repo: MakeRepo, invoke: Invoke) -> None:
    root = make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)
    _with_open_questions()

    data = json.loads(invoke("--root", str(root), "--format", "json").stdout)

    assert set(data["sections"]) == {"errors", "missing", "todo", "review", "info"}
    assert [d["subject"] for d in data["sections"]["todo"]] == [
        "app#description",
        "parties/acme#address",
        "parties/acme#email",
    ]
    assert data["sections"]["todo"][1]["note"] == "ask legal"
    assert data["sections"]["errors"] == []


# ---------------------------------------------------------------------------
# Root resolution without --root
# ---------------------------------------------------------------------------


def test_root_defaults_to_enclosing_git_checkout(
    make_repo: MakeRepo, invoke: Invoke, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = make_repo(snow=SNOW_TWO_UNITS, dirs=(*CODE_DIRS, "front/src"), seed=True)
    monkeypatch.chdir(root / "front" / "src")

    result = invoke("--format", "json")

    assert result.exit_code == 0
    assert json.loads(result.stdout)["root"] == str(root.resolve())


# ---------------------------------------------------------------------------
# Declaration and usage failures
# ---------------------------------------------------------------------------


def test_missing_manifest_exits_three(make_repo: MakeRepo, invoke: Invoke) -> None:
    root = make_repo(dirs=CODE_DIRS, seed=True)

    result = invoke("--root", str(root))

    assert result.exit_code == 3
    assert "No snow.yml" in result.output


def test_nonexistent_root_is_a_usage_error(invoke: Invoke, tmp_path: Path) -> None:
    result = invoke("--root", str(tmp_path / "nope"))

    assert result.exit_code == 2
    # rich-click draws a box and may wrap the sentence; match on the option name.
    assert "--root" in result.output
    assert "Usage:" in result.output


# ---------------------------------------------------------------------------
# Tool error
# ---------------------------------------------------------------------------


def test_unexpected_exception_exits_four_on_stderr(
    make_repo: MakeRepo, invoke: Invoke, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)

    def boom(*_args: object, **_kwargs: object) -> None:
        msg = "disk on fire"
        raise RuntimeError(msg)

    monkeypatch.setattr("model_wtf.compliance.cli.run_check", boom)

    result = invoke("--root", str(root))

    assert result.exit_code == 4
    assert "Tool error" in result.stderr
    assert "disk on fire" in result.stderr
    assert result.stdout == ""


def test_global_root_option(make_repo: MakeRepo) -> None:
    """``model-wtf --root X compliance ...`` applies to every subcommand."""
    root = make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)
    runner = CliRunner()

    result = runner.invoke(cli, ["--root", str(root), "compliance", "check"])
    assert result.exit_code == 0, result.output

    listed = runner.invoke(
        cli, ["--root", str(root), "compliance", "data", "list", "--format", "json"]
    )
    assert listed.exit_code == 0, listed.output


def test_version_flag_reports_the_installed_distribution() -> None:
    out = CliRunner().invoke(cli, ["--version"])
    assert out.exit_code == 0, out.output
    # The number itself comes from the tag at release time (0.0.0 in a
    # checkout); the flag must exist and name the distribution.
    assert out.output.startswith("model-wtf, version ")
