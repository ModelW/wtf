"""``compliance init``: the database, snow patching, idempotence."""

from __future__ import annotations

from typing import TYPE_CHECKING

from click.testing import CliRunner

from conftest import SNOW_FRONT_UNDECLARED
from model_wtf.cli import cli
from model_wtf.compliance.check import run_check
from model_wtf.compliance.container import DB_FILE, configure
from model_wtf.compliance.declarations import load_declarations
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.init_cmd import (
    PartySpec,
    detect_dockerfiles,
    guess_discovery,
    run_init,
    slugify,
)
from model_wtf.compliance.yaml_io import TODO, load_yaml

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
      compliance:
          discover: sveltekit

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
    root = make_repo(snow=SNOW_FRONT_UNDECLARED, dirs=("api", "front"))

    result = run_init(
        app_name="Kerfufoo",
        controller=PartySpec(name="ACME Corp", country="FR"),
        processor=PartySpec(
            name="WITH Madrid SL", country="ES", address="Madrid", email="dpo@w.es"
        ),
    )

    assert sorted(result.created) == [
        ".github/workflows/compliance.yml",
        DB_FILE,
        "db:app",
        "db:parties/acme-corp",
        "db:parties/with-madrid-sl",
    ]
    assert result.patched == [
        "snow.yml: images[front].compliance.discover = none",
        ".gitignore (SQLite transient files)",
    ]
    # No folder anywhere: the database is the whole scaffold.
    assert not (root / "compliance").exists()
    assert not (root / "api" / "compliance").exists()
    assert (root / DB_FILE).is_file()
    gitignore = (root / ".gitignore").read_text()
    assert "*.db-wal" in gitignore
    assert "*.db-shm" in gitignore
    assert "*.db-lock" in gitignore

    decl = load_declarations()
    assert decl.app is not None
    assert (decl.app.name, decl.app.description) == ("Kerfufoo", TODO)
    assert (decl.app.controller, decl.app.processor) == ("acme-corp", "with-madrid-sl")
    acme = decl.parties["acme-corp"]
    assert (acme.name, acme.country, acme.address, acme.email) == (
        "ACME Corp",
        "FR",
        TODO,
        TODO,
    )
    with_ = decl.parties["with-madrid-sl"]
    assert with_.address == "Madrid"
    assert with_.phone is None

    # The scaffold validates; only todos remain.
    report = run_check(strict=True)
    assert report.exit_code is ExitCode.FINDINGS
    assert sorted(d.message.split(": ", 1)[1] for d in report.diagnostics) == [
        "address is !todo",
        "description is !todo",
        "email is !todo",
    ]


def test_snow_patch_preserves_comments_and_existing_keys(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_WITH_COMMENTS)

    result = run_init(
        app_name="x",
        controller=PartySpec(name="A", country="FR"),
        processor=None,
    )

    text = (root / "snow.yml").read_text(encoding="utf-8")
    assert "# deployment manifest" in text
    assert "context: api   # django" in text
    assert text.count("discover:") == 2
    assert (
        "context: api   # django\n      compliance:\n          discover: none\n" in text
    )
    assert "snow.yml: images[api].compliance.discover = none" in result.patched
    assert not (root / "api").exists()  # init creates no folders
    decl = load_declarations()
    assert decl.app is not None
    assert decl.app.processor is None


def test_snow_patch_touches_only_the_added_lines(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_FOLDED)

    run_init(
        app_name="x",
        controller=PartySpec(name="A", country="FR"),
        processor=None,
    )

    text = (root / "snow.yml").read_text(encoding="utf-8")
    block = ["      compliance:", "          discover: none"]
    added = [line for line in text.splitlines() if line in block]
    assert added == block * 2
    without = "\n".join(line for line in text.splitlines() if line not in block)
    assert without + "\n" == SNOW_FOLDED
    # Inserted right after ``envs``, before the todo line.
    assert "envs: [sentry-build]\n" + "\n".join(block) + "\n\ncomponents" in text


def test_discovery_engine_is_guessed_from_the_code_folder(make_repo: MakeRepo) -> None:
    root = make_repo(
        snow=SNOW_FOLDED,
        files={
            "api/manage.py": "",
            "front/package.json": '{"devDependencies": {"@sveltejs/kit": "2"}}',
        },
    )

    result = run_init(
        app_name="x",
        controller=PartySpec(name="A", country="FR"),
        processor=None,
    )

    assert result.patched[:2] == [
        "snow.yml: images[api].compliance.discover = django",
        "snow.yml: images[front].compliance.discover = sveltekit",
    ]
    assert guess_discovery(root / "api") == "django"
    assert guess_discovery(root / "front") == "sveltekit"
    assert guess_discovery(root) == "none"


def test_init_is_idempotent(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_FRONT_UNDECLARED)
    spec = {
        "app_name": "x",
        "controller": PartySpec(name="A", country="FR"),
        "processor": None,
    }
    run_init(**spec)
    snow_before = (root / "snow.yml").read_text(encoding="utf-8")
    gitignore_before = (root / ".gitignore").read_text(encoding="utf-8")

    second = run_init(**{**spec, "app_name": "edited"})

    assert not second.changed
    assert "db:app" in second.skipped
    decl = load_declarations()
    assert decl.app is not None
    assert decl.app.name == "x"  # never overwritten
    assert (root / "snow.yml").read_text(encoding="utf-8") == snow_before
    assert (root / ".gitignore").read_text(encoding="utf-8") == gitignore_before


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
        app_name="x",
        controller=PartySpec(name="A", country="FR"),
        processor=None,
        manifest_units=proposed,
    )

    manifest = load_yaml(root / ".model-wtf.yml")
    assert manifest == {
        "units": [
            {"id": "api", "context": "api", "compliance": {"discover": "none"}},
            {"id": "front", "context": "front", "compliance": {"discover": "none"}},
        ]
    }
    assert not (root / "api" / "compliance").exists()


def test_custom_vocabulary_is_seeded_into_the_database(make_repo: MakeRepo) -> None:
    from model_wtf.compliance.knowledge import load_knowledge

    make_repo(snow=SNOW_FRONT_UNDECLARED)
    result = run_init(
        app_name="x",
        controller=PartySpec(name="A", country="FR"),
        processor=None,
        custom_sensitivity=True,
        custom_categories=True,
    )
    assert "db:sensitivity/confidential" in result.created
    assert "db:categories/health" in result.created
    knowledge = load_knowledge()
    assert knowledge.ordered_levels() == [
        "public",
        "internal",
        "personal",
        "confidential",
        "special",
    ]
    # Seeding again changes nothing.
    again = run_init(
        app_name="x",
        controller=PartySpec(name="A", country="FR"),
        processor=None,
        custom_sensitivity=True,
    )
    assert "db:sensitivity/confidential" in again.skipped


def test_cli_fails_clearly_without_tty(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_FRONT_UNDECLARED)

    result = CliRunner().invoke(
        cli, ["compliance", "init", "--root", str(root), "--name", "x"]
    )

    assert result.exit_code == 2
    assert "Controller legal name" in result.output
    assert not (root / DB_FILE).exists()


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
    configure(root)
    assert load_declarations().parties["acme"].country == "FR"


def test_init_writes_the_gate_workflow_unless_told_not_to(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_FRONT_UNDECLARED)
    spec = {
        "app_name": "x",
        "controller": PartySpec(name="A", country="FR"),
        "processor": None,
    }
    workflow = root / ".github" / "workflows" / "compliance.yml"
    run_init(**spec, workflow=False)
    assert not workflow.exists()
    run_init(**spec)
    assert "uses: ModelW/wtf@v1" in workflow.read_text()
    # Never overwritten.
    workflow.write_text("mine\n")
    run_init(**spec)
    assert workflow.read_text() == "mine\n"
