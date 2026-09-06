"""``model-wtf compliance check`` end-to-end through CliRunner."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

import pytest

from conftest import FILES_ALL_OK, SNOW_FRONT_UNDECLARED, SNOW_TWO_UNITS

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import Invoke, MakeRepo


# ---------------------------------------------------------------------------
# Happy path: text
# ---------------------------------------------------------------------------


def test_text_output_lists_all_scopes(make_repo: MakeRepo, invoke: Invoke) -> None:
    root = make_repo(snow=SNOW_TWO_UNITS, files=FILES_ALL_OK)

    result = invoke("--root", str(root))

    assert result.exit_code == 0
    assert "Compliance scopes" in result.output
    for scope_id in ("shared", "api", "front"):
        assert re.search(rf"\b{scope_id}\b", result.output)
    assert "front/compliance" in result.output
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
    root = make_repo(snow=snow, files=FILES_ALL_OK)
    args = ["--root", str(root), "--format", "json"]
    if strict:
        args.append("--strict")

    result = invoke(*args)

    assert result.exit_code == expected_exit
    data = json.loads(result.stdout)
    assert set(data) == {"root", "manifest", "scopes", "diagnostics", "exit_code"}
    assert data["exit_code"] == expected_exit
    assert data["manifest"] == "snow.yml"


# ---------------------------------------------------------------------------
# GitHub annotations
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("extra", "severity", "expected_exit"),
    [
        pytest.param((), "warning", 0, id="lenient"),
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
    root = make_repo(snow=SNOW_FRONT_UNDECLARED, files=FILES_ALL_OK)

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


@pytest.mark.parametrize(
    ("snow", "files", "fragment"),
    [
        pytest.param(
            SNOW_FRONT_UNDECLARED, FILES_ALL_OK, "declares no", id="unit-no-compliance"
        ),
    ],
)
def test_strict_turns_exit_zero_into_three(
    make_repo: MakeRepo, invoke: Invoke, snow: str, files: dict[str, str], fragment: str
) -> None:
    root = make_repo(snow=snow, files=files)

    lenient = invoke("--root", str(root))
    strict = invoke("--root", str(root), "--strict")

    assert lenient.exit_code == 0
    assert "warning" in lenient.output
    assert strict.exit_code == 3
    assert "error" in strict.output
    for result in (lenient, strict):
        assert fragment in result.output


# ---------------------------------------------------------------------------
# Root resolution without --root
# ---------------------------------------------------------------------------


def test_root_defaults_to_enclosing_git_checkout(
    make_repo: MakeRepo, invoke: Invoke, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = make_repo(snow=SNOW_TWO_UNITS, files=FILES_ALL_OK, dirs=("front/src",))
    monkeypatch.chdir(root / "front" / "src")

    result = invoke("--format", "json")

    assert result.exit_code == 0
    assert json.loads(result.stdout)["root"] == str(root.resolve())


# ---------------------------------------------------------------------------
# Declaration and usage failures
# ---------------------------------------------------------------------------


def test_missing_manifest_exits_three(make_repo: MakeRepo, invoke: Invoke) -> None:
    root = make_repo(files=FILES_ALL_OK)

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
    root = make_repo(snow=SNOW_TWO_UNITS, files=FILES_ALL_OK)

    def boom(*_args: object, **_kwargs: object) -> None:
        msg = "disk on fire"
        raise RuntimeError(msg)

    monkeypatch.setattr("model_wtf.compliance.cli.run_check", boom)

    result = invoke("--root", str(root))

    assert result.exit_code == 4
    assert "Tool error" in result.stderr
    assert "disk on fire" in result.stderr
    assert result.stdout == ""
