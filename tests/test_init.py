"""``compliance init``: scaffold content, snow patching, idempotence."""

from __future__ import annotations

from typing import TYPE_CHECKING

from click.testing import CliRunner

from conftest import SNOW_FRONT_UNDECLARED
from model_wtf.cli import cli
from model_wtf.compliance.check import run_check
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.init_cmd import (
    PartySpec,
    detect_dockerfiles,
    run_init,
    slugify,
)
from model_wtf.compliance.yaml_io import OPEN, load_yaml

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import MakeRepo

SNOW_WITH_COMMENTS = """\
# deployment manifest
images:
    - id: api
      context: api   # django
    - id: front
      context: .
      dockerfile: front/Dockerfile
      compliance: compliance

components: []
"""

SNOW_FOLDED = """\
images:
    - id: api
      context: api
    - id: front
      context: .
      dockerfile: front/Dockerfile
      envs: [sentry-build]

components:
    - id: api-worker
      image: api
      run_command:
          uv run --no-sync python manage.py procrastinate worker --concurrency
          10
"""


def test_slugify() -> None:
    assert slugify("WITH Madrid S.L.") == "with-madrid-sl"
    assert slugify("Société Générale") == "societe-generale"
    assert slugify("!!!") == "party"


def test_scaffold_is_complete_and_checkable(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_FRONT_UNDECLARED)

    result = run_init(
        root,
        app_name="Kerfufoo",
        controller=PartySpec(name="ACME Corp", country="FR"),
        processor=PartySpec(
            name="WITH Madrid SL", country="ES", address="Madrid", email="dpo@w.es"
        ),
    )

    rel = sorted(str(p.relative_to(root)) for p in result.created)
    assert rel == [
        "api/compliance",
        "compliance/README.md",
        "compliance/app.yaml",
        "compliance/parties/acme-corp.yaml",
        "compliance/parties/with-madrid-sl.yaml",
        "front/compliance",
    ]
    assert result.patched == ["snow.yml: images[front].compliance"]

    app = load_yaml(root / "compliance/app.yaml")
    assert app == {
        "name": "Kerfufoo",
        "description": OPEN,
        "controller": "acme-corp",
        "processor": "with-madrid-sl",
    }
    acme = load_yaml(root / "compliance/parties/acme-corp.yaml")
    assert acme == {
        "name": "ACME Corp",
        "country": "FR",
        "address": OPEN,
        "email": OPEN,
    }
    with_ = load_yaml(root / "compliance/parties/with-madrid-sl.yaml")
    assert with_["address"] == "Madrid"
    assert "phone" not in with_

    # The scaffold validates; only blanks remain.
    report = run_check(root, strict=True)
    assert report.exit_code is ExitCode.FINDINGS
    assert sorted(d.message.split(": ", 1)[1] for d in report.diagnostics) == [
        "address is still !open",
        "description is still !open",
        "email is still !open",
    ]


def test_snow_patch_preserves_comments_and_existing_keys(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_WITH_COMMENTS)

    result = run_init(
        root,
        app_name="x",
        controller=PartySpec(name="A", country="FR"),
        processor=None,
    )

    text = (root / "snow.yml").read_text(encoding="utf-8")
    assert "# deployment manifest" in text
    assert "context: api   # django" in text
    assert text.count("compliance: compliance") == 2
    assert result.patched == ["snow.yml: images[api].compliance"]
    assert (root / "api/compliance/.gitkeep").is_file()
    # front has context ".": its unit folder is the shared one, no .gitkeep.
    assert not (root / "compliance/.gitkeep").exists()
    assert "processor" not in load_yaml(root / "compliance/app.yaml")


def test_snow_patch_touches_only_the_added_lines(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_FOLDED)

    run_init(
        root,
        app_name="x",
        controller=PartySpec(name="A", country="FR"),
        processor=None,
    )

    text = (root / "snow.yml").read_text(encoding="utf-8")
    added = [line for line in text.splitlines() if "compliance: compliance" in line]
    assert added == ["      compliance: compliance"] * 2
    without = "\n".join(
        line for line in text.splitlines() if "compliance: compliance" not in line
    )
    assert without + "\n" == SNOW_FOLDED
    # Inserted right after ``envs``, before the blank line.
    assert "envs: [sentry-build]\n      compliance: compliance\n\ncomponents" in text


def test_init_is_idempotent(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_FRONT_UNDECLARED)
    spec = {
        "app_name": "x",
        "controller": PartySpec(name="A", country="FR"),
        "processor": None,
    }
    run_init(root, **spec)
    (root / "compliance/app.yaml").write_text("name: edited\n", encoding="utf-8")
    snow_before = (root / "snow.yml").read_text(encoding="utf-8")

    second = run_init(root, **spec)

    assert not second.changed
    assert (root / "compliance/app.yaml").read_text(
        encoding="utf-8"
    ) == "name: edited\n"
    assert (root / "snow.yml").read_text(encoding="utf-8") == snow_before


def test_without_snow_a_fallback_manifest_is_proposed(make_repo: MakeRepo) -> None:
    root = make_repo(
        files={
            "api/Dockerfile": "FROM x",
            "front/Dockerfile": "FROM y",
            "node_modules/z/Dockerfile": "FROM z",
        }
    )
    proposed = detect_dockerfiles(root)
    assert proposed == [("api", "api"), ("front", "front")]

    run_init(
        root,
        app_name="x",
        controller=PartySpec(name="A", country="FR"),
        processor=None,
        manifest_units=proposed,
    )

    manifest = load_yaml(root / ".model-wtf.yml")
    assert manifest == {
        "units": [
            {"id": "api", "context": "api", "compliance": "compliance"},
            {"id": "front", "context": "front", "compliance": "compliance"},
        ]
    }
    assert (root / "api/compliance/.gitkeep").is_file()


def test_cli_fails_clearly_without_tty(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_FRONT_UNDECLARED)

    result = CliRunner().invoke(
        cli, ["compliance", "init", "--root", str(root), "--name", "x"]
    )

    assert result.exit_code == 2
    assert "Controller legal name" in result.output
    assert not (root / "compliance").exists()


def test_cli_runs_with_all_options(make_repo: MakeRepo, tmp_path: Path) -> None:
    root = make_repo(snow=SNOW_FRONT_UNDECLARED)

    result = CliRunner().invoke(
        cli,
        [
            "compliance",
            "init",
            "--root",
            str(root),
            "--name",
            "Kerfufoo",
            "--controller-name",
            "ACME",
            "--controller-country",
            "fr",
            "--no-processor",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "created" in result.output
    assert "next:" in result.output
    assert load_yaml(root / "compliance/parties/acme.yaml")["country"] == "FR"
