"""Surface v1 schema, Django runner detection, `.gen.yaml` writer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import yaml

from model_wtf.auto.run import AutoOptions, run_auto
from model_wtf.extractors.django import (
    detect_runner,
    find_manage,
    is_django_unit,
    load_surface_file,
    run_extractor,
)
from model_wtf.extractors.surface import SCHEMA_ID, SurfaceError, parse_surface
from model_wtf.extractors.writer import egress_slug, write_surface
from model_wtf.knowledge.loader import load_knowledge

if TYPE_CHECKING:
    from conftest import MakeRepo

SURFACE = Path(__file__).parent / "eval" / "surfaces" / "template-api.surface.json"
SNOW = "images:\n  - id: api\n    context: api\n    compliance: compliance\n"


def _files(folder: Path) -> dict[str, str]:
    return {
        p.relative_to(folder).as_posix(): p.read_text()
        for p in folder.rglob("*.gen.yaml")
    }


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_surface_fixture_validates() -> None:
    surface = load_surface_file(SURFACE)
    assert surface.schema_ == SCHEMA_ID
    assert surface.unit == "api"
    assert [s.id for s in surface.storage][:2] == [
        "store:people.User",
        "store:cms.CustomImage",
    ]
    assert surface.entrypoints[0].auth.scheme == "none"


def test_surface_rejects_bad_schema_and_shape(tmp_path: Path) -> None:
    with pytest.raises(SurfaceError, match="unsupported surface schema"):
        parse_surface({"schema": "modelw.surface/9", "unit": "x"})
    with pytest.raises(SurfaceError, match="does not match"):
        parse_surface({"schema": SCHEMA_ID})
    bad = tmp_path / "s.json"
    bad.write_text("{not json")
    with pytest.raises(SurfaceError, match="cannot read"):
        load_surface_file(bad)


def test_surface_keeps_unknown_facts() -> None:
    surface = parse_surface(
        {
            "schema": SCHEMA_ID,
            "unit": "x",
            "storage": [
                {
                    "id": "store:a.B",
                    "app_label": "a",
                    "model": "B",
                    "fields": [{"name": "f", "type": "T", "future_fact": 1}],
                }
            ],
        }
    )
    assert surface.storage[0].fields[0].model_extra == {"future_fact": 1}


# ---------------------------------------------------------------------------
# Runner detection
# ---------------------------------------------------------------------------


def test_is_django_unit(tmp_path: Path) -> None:
    ctx = tmp_path / "api"
    ctx.mkdir()
    assert not is_django_unit(ctx)
    (ctx / "pyproject.toml").write_text('[project]\nname="x"\ndependencies=["httpx"]\n')
    assert not is_django_unit(ctx)
    (ctx / "pyproject.toml").write_text(
        '[project]\nname="x"\ndependencies=["Django>=5"]\n'
    )
    assert is_django_unit(ctx)
    (ctx / "pyproject.toml").write_text(
        '[project]\nname="x"\ndependencies=[]\n[project.optional-dependencies]\n'
        'api=["modelw_preset_django"]\n'
    )
    assert is_django_unit(ctx)
    (ctx / "pyproject.toml").write_text('[tool.poetry.dependencies]\ndjango="^5"\n')
    assert is_django_unit(ctx)


def test_detect_runner_prefers_lockfiles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = tmp_path / "api"
    ctx.mkdir()
    monkeypatch.setattr(
        "model_wtf.extractors.django.shutil.which", lambda name: f"/bin/{name}"
    )
    assert detect_runner(ctx).kind == "python"  # type: ignore[union-attr]
    (ctx / "poetry.lock").write_text("")
    assert detect_runner(ctx).kind == "poetry"  # type: ignore[union-attr]
    (ctx / "uv.lock").write_text("")
    runner = detect_runner(ctx)
    assert runner is not None
    assert runner.kind == "uv"
    assert runner.command(ctx / "manage.py")[-2:] == [
        "export_compliance_surface",
        "--json",
    ]
    monkeypatch.setattr("model_wtf.extractors.django.shutil.which", lambda name: None)
    assert detect_runner(ctx) is None


def test_find_manage(tmp_path: Path) -> None:
    ctx = tmp_path / "api"
    (ctx / ".venv" / "x").mkdir(parents=True)
    (ctx / ".venv" / "x" / "manage.py").write_text("")
    assert find_manage(ctx) is None
    (ctx / "src").mkdir()
    (ctx / "src" / "manage.py").write_text("")
    assert find_manage(ctx) == ctx / "src" / "manage.py"
    (ctx / "manage.py").write_text("")
    assert find_manage(ctx) == ctx / "manage.py"


def test_run_extractor_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = tmp_path / "api"
    ctx.mkdir()
    with pytest.raises(SurfaceError, match=r"no manage\.py"):
        run_extractor(ctx)
    (ctx / "manage.py").write_text("")
    monkeypatch.setattr("model_wtf.extractors.django.shutil.which", lambda name: None)
    with pytest.raises(SurfaceError, match="no Python runner"):
        run_extractor(ctx)


def test_run_extractor_executes_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = tmp_path / "api"
    ctx.mkdir()
    # A fake manage.py: any `python manage.py export_compliance_surface --json`
    # prints the recorded surface.
    (ctx / "manage.py").write_text(
        f"import sys, pathlib\nprint(pathlib.Path({str(SURFACE)!r}).read_text())\n"
    )
    monkeypatch.setattr(
        "model_wtf.extractors.django.shutil.which",
        lambda name: "/usr/bin/python3" if name == "python3" else None,
    )
    surface = run_extractor(ctx)
    assert surface.unit == "api"


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------


def test_writer_outputs_and_idempotency(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW, dirs=("api/compliance",))
    folder = root / "api/compliance"
    surface = load_surface_file(SURFACE)

    first = write_surface(folder, surface, source_sha="abc")
    files = _files(folder)

    assert set(files) == {
        "elements/unit.gen.yaml",
        "data/people.user.gen.yaml",
        "data/cms.customimage.gen.yaml",
        "data/cms.homepage.gen.yaml",
        "data/sessions.session.gen.yaml",
        "recipients/sentry.gen.yaml",
        "recipients/digitalocean-spaces.gen.yaml",
        "recipients/unknown-vendor.gen.yaml",
    }
    assert all(
        t.startswith("# GENERATED by model-wtf \u2014 do not edit; edit ")
        for t in files.values()
    )
    assert (
        files["data/people.user.gen.yaml"]
        .splitlines()[0]
        .endswith("edit people.user.yaml")
    )

    user = yaml.safe_load(files["data/people.user.gen.yaml"])
    assert user["by"] == "extractor"
    assert user["sources"] == ["store:people.User"]
    assert user["fields"]["email"] == {
        "type": "EmailField",
        "suggested": "email",
        "confidence": "high",
        "unique": True,
    }
    assert user["fields"]["preferences"] == {
        "type": "JSONField",
        "opaque": True,
        "candidate_contents": ["locale", "newsletter"],
    }
    assert user["pii_suspected"] is True
    homepage = yaml.safe_load(files["data/cms.homepage.gen.yaml"])
    assert (
        homepage["pii_suspected"] is True
    )  # opaque field -> suspected until classified
    session = yaml.safe_load(files["data/sessions.session.gen.yaml"])
    assert session["shadow_store"] is True

    sentry = yaml.safe_load(files["recipients/sentry.gen.yaml"])
    assert sentry["suggested"] == {
        "name": "Sentry",
        "kind": "processor",
        "third_country": "US",
        "sink": True,
    }
    assert sentry["detection"] == {
        "packages": ["sentry_sdk"],
        "hosts": [],
        "env": ["SENTRY_DSN"],
    }
    assert sentry["facts"] == {"send_default_pii": False}
    assert sentry["units"] == ["api"]
    spaces = yaml.safe_load(files["recipients/digitalocean-spaces.gen.yaml"])
    assert spaces["suggested"]["kind"] == "processor"
    assert "third_country" not in spaces["suggested"]
    unknown = yaml.safe_load(files["recipients/unknown-vendor.gen.yaml"])
    assert "suggested" not in unknown

    unit = yaml.safe_load(files["elements/unit.gen.yaml"])
    assert unit["source_sha"] == "abc"
    assert [e["id"] for e in unit["entrypoints"]][:2] == [
        "http:GET:/back/api/me/",
        "http:GET:/back/api/pages/",
    ]
    assert unit["tasks"][0]["schedule"] == "0 3 * * *"
    assert unit["controls"]["DEBUG"] is False

    second = write_surface(folder, surface, source_sha="abc")
    assert second.changed == []
    assert _files(folder) == files
    assert len(first.changed) == len(files)


def test_no_pii_model_is_flagged_false(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW, dirs=("api/compliance",))
    surface = parse_surface(
        {
            "schema": SCHEMA_ID,
            "unit": "api",
            "storage": [
                {
                    "id": "store:shop.Sku",
                    "app_label": "shop",
                    "model": "Sku",
                    "fields": [{"name": "code", "type": "CharField"}],
                }
            ],
        }
    )
    write_surface(root / "api/compliance", surface)
    sku = yaml.safe_load((root / "api/compliance/data/shop.sku.gen.yaml").read_text())
    assert sku["pii_suspected"] is False


def test_egress_slug_matching() -> None:
    catalogue = load_knowledge().egress
    from model_wtf.extractors.surface import Egress

    assert egress_slug(Egress(id="egress:sdk:stripe"), catalogue) == "stripe"
    assert (
        egress_slug(Egress(id="egress:host:o1.ingest.sentry.io"), catalogue) == "sentry"
    )
    assert (
        egress_slug(
            Egress(id="egress:sdk:foo", credential_keys=["MANDRILL_API_KEY"]), catalogue
        )
        == "mandrill"
    )
    assert egress_slug(Egress(id="egress:host:api.example.co.uk"), catalogue) == "co"
    assert egress_slug(Egress(id="egress:sdk:Some_Lib"), catalogue) == "some-lib"


# ---------------------------------------------------------------------------
# Integration with auto
# ---------------------------------------------------------------------------


class NoWorker:
    """A worker that must never be asked anything."""

    def ask(self, agent: str, prompt: str, *, model: str | None, title: str):  # type: ignore[no-untyped-def]
        msg = "agent must not be called"
        raise AssertionError(msg)

    def follow_up(self, session_id: str, prompt: str):  # type: ignore[no-untyped-def]
        raise AssertionError

    @property
    def cost_usd(self) -> float:
        return 0.0

    def usage_dict(self) -> dict[str, object]:
        return {"cost_usd": 0.0, "sessions": 0}


def test_auto_uses_surface_file_instead_of_agent(make_repo: MakeRepo) -> None:
    from model_wtf.auto.routing import Routing

    root = make_repo(snow=SNOW, dirs=("api/compliance",))
    (root / "api/pyproject.toml").write_text(
        '[project]\nname="api"\ndependencies=["django"]\n'
    )
    options = AutoOptions(stages=("discover",), surface={"api": SURFACE})

    report = run_auto(root, NoWorker(), Routing(default="openrouter/x/y"), options)

    assert report.stages["extract"].done == 1
    assert "discover" in report.stages
    assert report.stages["discover"].items == 0  # Django unit: no agent discover
    assert (root / "api/compliance/data/people.user.gen.yaml").exists()

    # Human files, ledgers, findings untouched by a second run with the same surface.
    human = root / "api/compliance/data/people.user.yaml"
    human.write_text(
        "name: Your account\ndescription: d\nfields:\n  email: {item: email}\n"
        "subject_categories: []\nidentification: identified\nrectification: dpo\n"
    )
    before = human.read_text()
    again = run_auto(root, NoWorker(), Routing(default="openrouter/x/y"), options)
    assert again.stages["extract"].done == 1  # explicit --surface always rewrites
    assert human.read_text() == before


def test_django_unit_without_surface_reports_failure_not_agent(
    make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    from model_wtf.auto.routing import Routing

    root = make_repo(snow=SNOW, dirs=("api/compliance",))
    (root / "api/pyproject.toml").write_text(
        '[project]\nname="api"\ndependencies=["django"]\n'
    )
    monkeypatch.setattr("model_wtf.extractors.django.shutil.which", lambda name: None)

    report = run_auto(
        root,
        NoWorker(),
        Routing(default="openrouter/x/y"),
        AutoOptions(stages=("discover",)),
    )

    assert report.stages["extract"].failed == 1
    assert "no manage.py" in next(iter(report.stages["extract"].failures.values()))
    assert report.stages["discover"].items == 0


def test_surface_json_roundtrip_matches_writer(
    make_repo: MakeRepo, tmp_path: Path
) -> None:
    """`--surface file` and running the command produce the same files."""
    root = make_repo(snow=SNOW, dirs=("api/compliance",))
    surface = load_surface_file(SURFACE)
    write_surface(root / "api/compliance", surface, source_sha="x")
    via_file = _files(root / "api/compliance")

    other = make_repo(snow=SNOW, dirs=("api/compliance",))
    write_surface(
        other / "api/compliance",
        parse_surface(json.loads(SURFACE.read_text())),
        source_sha="x",
    )
    assert _files(other / "api/compliance") == via_file
