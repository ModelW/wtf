"""Review lock, MCP tools, and the sandboxed OpenCode configuration."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from conftest import FILES_ALL_OK
from model_wtf.cli import cli
from model_wtf.compliance.check import run_check
from model_wtf.compliance.data import collect_unit
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.knowledge import load_knowledge
from model_wtf.compliance.mcp_server import (
    ContentDecision,
    Decision,
    Tools,
    field_of,
    model_of,
)
from model_wtf.compliance.report import Unit
from model_wtf.compliance.review import Lock, ReviewStatus
from model_wtf.opencode import (
    Agent,
    McpServer,
    OpenCodeUnavailable,
    Sandbox,
    parse_events,
    preflight,
)

if TYPE_CHECKING:
    from conftest import MakeRepo

FIXTURE = Path(__file__).parent / "fixtures" / "djproj"
SNOW_DJANGO = """
images:
  - id: api
    context: api
    compliance:
      discover: django
"""


@pytest.fixture
def repo(make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = make_repo(snow=SNOW_DJANGO, files=FILES_ALL_OK)
    shutil.copytree(FIXTURE, root / "api", dirs_exist_ok=True)
    (root / "api" / "compliance").mkdir(exist_ok=True)
    monkeypatch.setenv("MODEL_WTF_PYTHON", sys.executable)
    monkeypatch.delenv("DJANGO_SETTINGS_MODULE", raising=False)
    return root


def _unit(root: Path) -> Unit:
    return Unit("api", root / "api" / "compliance", "django", root / "api")


# ---------------------------------------------------------------------------
# Lock
# ---------------------------------------------------------------------------


def test_lock_lifecycle(repo: Path) -> None:
    unit = _unit(repo)
    rows = {r.id: r for r in collect_unit(unit, load_knowledge(None)).rows}
    lock = Lock(unit)

    email = rows["shop.Customer.email"]
    assert lock.status_of(email).status is ReviewStatus.PENDING_NEW
    assert lock.status_of(rows["auth.User.password"]).status is ReviewStatus.KNOWN
    assert (
        lock.status_of(rows["auth.Group.permissions"]).status
        is ReviewStatus.PENDING_NEW
    )

    lock.mark([email], by="human", note="plain email")
    lock.save()
    text = (unit.folder / "data.lock.yaml").read_text()
    assert "shop.Customer.email:" in text
    assert "by: human" in text

    again = Lock(unit)
    assert again.status_of(email).status is ReviewStatus.REVIEWED
    entry = again.data.items["shop.Customer.email"]
    assert entry.note == "plain email"
    assert entry.reviewed_at.tzinfo is not None

    # A different fingerprint (schema or verdict changed) re-opens the item.
    again.data.items["shop.Customer.email"].fingerprint = "00000000"
    assert again.status_of(email).status is ReviewStatus.PENDING_CHANGED

    # Entries for vanished fields are pruned.
    again.data.items["shop.Gone.field"] = again.data.items["shop.Customer.email"]
    assert again.prune(list(rows.values())) == ["shop.Gone.field"]


def test_invalid_lock_is_a_declaration_error(repo: Path) -> None:
    (repo / "api" / "compliance" / "data.lock.yaml").write_text("items: [1, 2]\n")

    report = run_check(repo, strict=False)

    assert "lock-invalid" in {d.code for d in report.diagnostics}
    assert report.exit_code is ExitCode.DECLARATION_ERROR


def test_override_and_reviewed_commands_write_the_lock(repo: Path) -> None:
    runner = CliRunner()
    root = ["--root", str(repo)]

    ok = runner.invoke(
        cli,
        [
            "compliance",
            "data",
            "override",
            "api:shop.Customer.email",
            *root,
            "--no-pii",
            "--reason",
            "x",
        ],
    )
    assert ok.exit_code == 0, ok.output
    rev = runner.invoke(
        cli,
        [
            "compliance",
            "data",
            "reviewed",
            "api:shop.Customer.phone",
            "api:shop.Order.total",
            *root,
            "--note",
            "checked",
        ],
    )
    assert rev.exit_code == 0, rev.output

    lock = Lock(_unit(repo))
    assert set(lock.data.items) == {
        "shop.Customer.email",
        "shop.Customer.phone",
        "shop.Order.total",
    }
    assert all(e.by == "human" for e in lock.data.items.values())

    listed = runner.invoke(
        cli, ["compliance", "data", "list", *root, "--pending", "--format", "json"]
    )
    ids = {r["id"] for r in json.loads(listed.output)}
    assert "shop.Customer.phone" not in ids
    assert "shop.Customer.email" not in ids
    assert "shop.Customer.iban" in ids
    assert "auth.User.password" not in ids  # known
    assert "auth.Group.permissions" in ids  # third-party, still reviewed

    bad = runner.invoke(
        cli, ["compliance", "data", "reviewed", "api:shop.Nope.x", *root]
    )
    assert bad.exit_code == 2


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------


def test_model_and_field_helpers() -> None:
    from model_wtf.compliance.data import Row, Source

    def row(item_id: str) -> Row:
        return Row("api", item_id, "x", True, "personal", "content", None, Source.RULE)

    assert model_of(row("shop.Customer.email")) == "shop.Customer"
    assert field_of(row("shop.Customer.email")) == "email"
    assert model_of(row("shop.Customer.avatar@files.content")) == "shop.Customer"
    assert field_of(row("shop.Customer.avatar@files.content")) == "avatar@files.content"


def test_tools_pending_model_review(repo: Path) -> None:
    tools = Tools(repo, batch=2)

    pending = tools.pending()
    assert "showing 2" in pending
    assert "api:shop.Customer |" in pending
    assert "project" in pending

    model = tools.model("api:shop.Customer")
    assert "class Customer(models.Model):" in model
    assert (
        "email | EmailField | pii=yes | personal | contact | email | pending" in model
    )
    assert "avatar@files.content (bytes behind `avatar`" in model
    assert "preferences" in model
    assert "write sites of JSON-like fields" in model

    result = tools.review_model(
        "api:shop.Customer",
        [
            Decision(field="email", ok=True),
            Decision(field="phone", ok=True),
            Decision(
                field="preferences",
                pii=False,
                category="technical",
                reason="UI theme only, models.py:14",
            ),
            Decision(field="notes", reason="nothing changes"),
            Decision(field="ghost", ok=True),
            Decision(field="iban", sensitivity="top", reason="x"),
            Decision(field="first_name", pii=True, reason="same as now"),
        ],
        note="looked at the class",
    )
    assert "2 confirmed, 1 overridden, 4 rejected" in result
    assert "rejected notes: not ok but nothing changes" in result
    assert "rejected ghost: not a field" in result
    assert "rejected iban: unknown sensitivity 'top'" in result
    assert "rejected first_name: values equal" in result
    assert "still pending" in result

    override = repo / "api" / "compliance" / "data" / "shop.Customer.preferences.yaml"
    assert (
        override.read_text()
        == 'pii: false\ncategory: technical\nreason: "UI theme only, models.py:14"\n'
    )
    lock = Lock(_unit(repo))
    assert lock.data.items["shop.Customer.email"].by == "agent"
    assert lock.data.items["shop.Customer.preferences"].note.startswith("UI theme")

    after = tools.model("api:shop.Customer")
    assert (
        "preferences | JSONField | pii=no | confidential | technical | json | override"
        in after
    )

    with pytest.raises(ValueError, match="unknown unit"):
        tools.unit("front")
    with pytest.raises(ValueError, match="must be"):
        tools.model_rows("shop.Customer")


def test_tools_changed_without_git_history(repo: Path) -> None:
    tools = Tools(repo)
    assert tools.changed("HEAD~1").startswith("nothing")


# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------


def test_sandbox_config_is_airtight(tmp_path: Path) -> None:
    box = Sandbox(
        readable=[tmp_path / "repo", tmp_path / "venv"],
        model="openrouter/x/y",
        mcp={"model-wtf": McpServer(command=["python", "-m", "x"])},
        agents={
            "dispatcher": Agent("d", "prompt", mode="primary", steps=5),
            "reviewer": Agent("r", "prompt", steps=7, permission={"task": "deny"}),
        },
        max_tokens=1000,
    )

    cfg = box.to_config()

    assert cfg["default_agent"] == "dispatcher"
    assert cfg["instructions"] == []
    assert cfg["share"] == "disabled"
    assert cfg["autoupdate"] is False
    assert cfg["snapshot"] is False
    assert cfg["enabled_providers"] == ["openrouter"]
    assert (
        cfg["provider"]["openrouter"]["options"]["apiKey"] == "{env:OPENROUTER_API_KEY}"
    )
    perm = cfg["permission"]
    assert perm["*"] == "deny"
    assert perm["edit"] == "deny"
    assert perm["bash"] == "deny"
    assert perm["webfetch"] == "deny"
    assert perm["model-wtf_*"] == "allow"
    assert perm["task"] == {"*": "deny", "reviewer": "allow"}
    ext = perm["external_directory"]
    assert ext["*"] == "deny"
    assert ext[f"{(tmp_path / 'repo').resolve()}/**"] == "allow"
    assert ext[f"{(tmp_path / 'venv').resolve()}/**"] == "allow"
    for builtin in ("build", "plan", "general", "explore"):
        assert cfg["agent"][builtin] == {"disable": True}
    assert cfg["agent"]["reviewer"]["steps"] == 7
    assert cfg["agent"]["reviewer"]["mode"] == "subagent"
    assert cfg["mcp"]["model-wtf"]["type"] == "local"


def test_preflight_errors(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    with pytest.raises(OpenCodeUnavailable, match="not on PATH"):
        preflight({"PATH": str(tmp_path)})

    fake = tmp_path / "opencode"
    fake.write_text("#!/bin/sh\necho 1.18.29\n")
    fake.chmod(0o755)
    with pytest.raises(OpenCodeUnavailable, match="OPENROUTER_API_KEY"):
        preflight({"PATH": str(tmp_path)})
    assert preflight({"PATH": str(tmp_path), "OPENROUTER_API_KEY": "k"}) == str(fake)

    old = tmp_path / "old" / "opencode"
    old.parent.mkdir()
    old.write_text("#!/bin/sh\necho 0.9.0\n")
    old.chmod(0o755)
    with pytest.raises(OpenCodeUnavailable, match="too old"):
        preflight({"PATH": str(old.parent), "OPENROUTER_API_KEY": "k"})


def test_parse_events_digest() -> None:
    lines = [
        json.dumps({"type": "step_start", "part": {}}),
        json.dumps({"type": "tool_use", "part": {"tool": "model-wtf_data_pending"}}),
        json.dumps(
            {
                "type": "step_finish",
                "part": {"tokens": {"total": 120}, "cost": 0.5, "modelID": "gemini"},
            }
        ),
        json.dumps({"type": "text", "part": {"text": "ROUND COMPLETE: 3 dispatched"}}),
        json.dumps({"type": "step_finish", "part": {"tokens": {"total": 30}}}),
        "not json",
    ]

    result = parse_events("\n".join(lines))

    assert result.tokens == 150
    assert result.cost == 0.5
    assert result.tool_calls == 1
    assert result.models == {"gemini"}
    assert result.final_text == "ROUND COMPLETE: 3 dispatched"


def test_auto_review_dry_run_and_missing_key(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = CliRunner()
    root = ["--root", str(repo)]

    dry = runner.invoke(cli, ["compliance", "data", "auto-review", *root, "--dry-run"])
    assert dry.exit_code == 0, dry.output
    cfg = json.loads(dry.output)
    assert cfg["default_agent"] == "dispatcher"
    assert any(
        str(repo.resolve()) in key for key in cfg["permission"]["external_directory"]
    )
    assert cfg["mcp"]["model-wtf"]["command"][1:5] == [
        "-m",
        "model_wtf",
        "compliance",
        "data",
    ]

    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("PATH", str(repo))  # no opencode binary here
    run = runner.invoke(cli, ["compliance", "data", "auto-review", *root])
    assert run.exit_code == 4


def test_tools_review_json_contents(repo: Path) -> None:
    tools = Tools(repo)

    shown = tools.model("api:shop.Customer")
    assert "write sites of JSON-like fields" in shown

    bare = tools.review_model(
        "api:shop.Customer", [Decision(field="preferences", ok=True)], note="n"
    )
    assert "rejected preferences: JSON fields need a contents declaration" in bare

    missing_unknown = tools.review_model(
        "api:shop.Customer",
        [
            Decision(
                field="preferences",
                contents={
                    "theme": ContentDecision(
                        pii=False, sensitivity="internal", category="technical"
                    )
                },
                reason="x",
            )
        ],
        note="n",
    )
    assert "unknown_contents (none|possible|likely) is required" in missing_unknown

    bad_vocab = tools.review_model(
        "api:shop.Customer",
        [
            Decision(
                field="preferences",
                contents={
                    "theme": ContentDecision(pii=False, sensitivity="top", category="x")
                },
                unknown_contents="none",
                reason="x",
            )
        ],
        note="n",
    )
    assert "theme: unknown sensitivity 'top'" in bad_vocab

    on_text = tools.review_model(
        "api:shop.Customer",
        [
            Decision(
                field="email",
                contents={},
                unknown_contents="none",
                reason="x",
            )
        ],
        note="n",
    )
    assert "is not a JSON-like column" in on_text

    ok = tools.review_model(
        "api:shop.Customer",
        [
            Decision(
                field="preferences",
                contents={
                    "theme": ContentDecision(
                        pii=False, sensitivity="internal", category="technical"
                    ),
                    "phone": ContentDecision(
                        pii=True, sensitivity="personal", category="contact"
                    ),
                },
                unknown_contents="possible",
                reason="shop/views.py:40 copies request data",
            )
        ],
        note="n",
    )
    assert "1 overridden" in ok
    path = repo / "api" / "compliance" / "data" / "shop.Customer.preferences.yaml"
    assert "unknown_contents: possible" in path.read_text()
    lock = Lock(_unit(repo))
    assert lock.data.items["shop.Customer.preferences@json.phone"].by == "agent"
    after = tools.model("api:shop.Customer")
    assert (
        "preferences@json.phone (declared content of `preferences`) | JsonContent | "
        "pii=yes | personal | contact" in after
    )
    assert "preferences | JSONField | pii=yes | personal | contact+technical" in after
