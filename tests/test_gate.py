"""``ghate``: base vs head comparison over a real git history."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from conftest import FILES_ALL_OK
from model_wtf.cli import cli
from model_wtf.compliance.check import run_check
from model_wtf.compliance.discovery import load_units, select_manifest
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.gate import (
    GateError,
    compare,
    findings_of,
    github_context,
    run_gate,
    summary_markdown,
)
from model_wtf.compliance.knowledge import load_knowledge
from model_wtf.compliance.report import Diagnostic, Report, Severity
from model_wtf.compliance.review import Lock
from model_wtf.compliance.workspace import load_workspace

if TYPE_CHECKING:
    from conftest import MakeRepo

FIXTURE = Path(__file__).parent / "fixtures" / "djproj"
ADDRESS = "address: 1 rue de la Paix, Paris"
SNOW_DJANGO = """
images:
  - id: api
    context: api
    compliance:
      discover: django
"""


def git(root: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603
        ["git", *args],  # noqa: S607
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
        env={
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@t",
            "PATH": "/usr/bin:/bin",
            "HOME": str(root),
        },
    ).stdout.strip()


def commit(root: Path, message: str) -> str:
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", message)
    return git(root, "rev-parse", "HEAD")


@pytest.fixture
def repo(make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A real git repository whose ``api`` unit is the fixture Django
    project, with the compliance folder committed on ``develop``."""
    root = make_repo(snow=SNOW_DJANGO, files=FILES_ALL_OK, git=False)
    shutil.copytree(FIXTURE, root / "api", dirs_exist_ok=True)
    monkeypatch.setenv("MODEL_WTF_PYTHON", sys.executable)
    monkeypatch.delenv("DJANGO_SETTINGS_MODULE", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    # No challenger in these tests: the gate itself is deterministic.
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("MODEL_WTF_WORKTREE_DIR", str(root.parent / "worktrees"))
    git(root, "init", "-q", "-b", "develop")
    (root / ".gitignore").write_text("__pycache__/\n")
    commit(root, "base")
    return root


def _rows(root: Path):
    units, _ = load_units(select_manifest(root), root, strict=False)
    ws = load_workspace(
        root,
        units,
        load_knowledge(root / "compliance"),
        python=None,
        with_touchpoints=False,
    )
    return units[0], ws.data["api"].rows


def _reviewed(root: Path, *ids: str) -> None:
    unit, rows = _rows(root)
    lock = Lock(unit)
    lock.mark([r for r in rows if r.id in ids], by="human", note="checked")
    lock.save()


def test_findings_are_keyed_by_identity_and_folds_explode_into_items() -> None:
    root = Path("/repo")
    folded = Diagnostic(
        Severity.WARNING,
        "pending-review",
        "2 data item(s) pending",
        "api",
        root / "api/compliance/data.lock.yaml",
        subject="api:data",
        items=("api:shop.Customer.email", "api:shop.Customer.phone"),
    )
    marker = Diagnostic(
        Severity.WARNING,
        "todo",
        "fah.yaml: address is !todo",
        "shared",
        root / "compliance/parties/fah.yaml",
        subject="fah.yaml#address",
    )
    info = Diagnostic(Severity.INFO, "data-unreferenced", "x", "api", items=("a",))
    report = Report(root, None, (), (folded, marker, info), ExitCode.FINDINGS)
    keys = set(findings_of(report))
    assert keys == {
        ("api", "pending-review", "api:shop.Customer.email"),
        ("api", "pending-review", "api:shop.Customer.phone"),
        ("shared", "todo", "fah.yaml#address"),
    }
    # Rewording the message changes nothing; the identity holds.
    reworded = Diagnostic(
        Severity.WARNING,
        "pending-review",
        "two items still pending",
        "api",
        None,
        subject="api:data",
        items=("api:shop.Customer.phone",),
    )
    base = Report(root, None, (), (reworded,), ExitCode.FINDINGS)
    result = compare(report, base, base_ref="develop")
    assert [f.subject for f in result.introduced] == [
        "api:shop.Customer.email",
        "fah.yaml#address",
    ]
    assert [f.subject for f in result.pre_existing] == ["api:shop.Customer.phone"]
    assert result.fixed == []
    assert result.exit_code is ExitCode.FINDINGS


def test_gate_on_the_same_tree_introduces_nothing(repo: Path) -> None:
    result = run_gate(repo, base_ref="develop")
    assert result.introduced == []
    assert result.fixed == []
    assert result.pre_existing  # the fixture has pending items
    assert result.exit_code is ExitCode.CLEAN
    assert result.exit_code_with(fail_on_existing=True) is ExitCode.FINDINGS
    # The worktree is gone.
    assert not list((repo.parent / "worktrees").glob("gate-*"))


def test_a_new_personal_field_is_the_only_introduced_finding(repo: Path) -> None:
    """Acceptance: a branch adding an unreviewed personal field fails with
    exactly one introduced finding; reviewing it makes the branch pass
    even though other items are still pending."""
    # Start from a base where everything is reviewed except what we add.
    _, rows = _rows(repo)
    _reviewed(repo, *[r.id for r in rows])
    commit(repo, "all reviewed")
    git(repo, "checkout", "-q", "-b", "feature")
    models = repo / "api" / "shop" / "models.py"
    models.write_text(
        models.read_text().replace(
            "    phone = models.CharField(max_length=20, blank=True)\n",
            "    phone = models.CharField(max_length=20, blank=True)\n"
            "    nickname = models.CharField(max_length=20, blank=True)\n",
        )
    )
    result = run_gate(repo, base_ref="develop")
    assert [(f.code, f.subject) for f in result.introduced] == [
        ("pending-review", "api:shop.Customer.nickname")
    ]
    assert result.exit_code is ExitCode.FINDINGS
    assert result.introduced[0].diagnostic.path is not None

    _reviewed(repo, "shop.Customer.nickname")
    result = run_gate(repo, base_ref="develop")
    assert result.introduced == []
    assert result.exit_code is ExitCode.CLEAN


def _open_question(repo: Path) -> Path:
    """Commit a ``!todo`` on the base so a branch can answer it."""
    party = repo / "compliance" / "parties" / "acme.yaml"
    party.write_text(party.read_text().replace(ADDRESS, "address: !todo"))
    commit(repo, "open question")
    return party


def test_fixing_a_todo_is_reported_as_fixed(repo: Path) -> None:
    party = _open_question(repo)
    party.write_text(party.read_text().replace("address: !todo", ADDRESS))
    result = run_gate(repo, base_ref="develop")
    fixed = [(f.code, f.subject) for f in result.fixed]
    assert ("todo", "acme.yaml#address") in fixed
    assert result.introduced == []


def test_declaration_errors_in_the_head_always_fail(repo: Path) -> None:
    (repo / "compliance" / "app.yaml").write_text("name: [\n")
    result = run_gate(repo, base_ref="develop")
    assert result.exit_code is ExitCode.DECLARATION_ERROR
    assert "Declaration errors" in summary_markdown(result)


def test_head_ref_gates_a_commit_instead_of_the_tree(repo: Path) -> None:
    party = _open_question(repo)
    git(repo, "checkout", "-q", "-b", "feature")
    party.write_text(party.read_text().replace("address: !todo", ADDRESS))
    commit(repo, "fill address")
    # Dirty the tree afterwards: --head ignores it.
    party.write_text(party.read_text().replace("email: privacy", "email: !todo #"))
    result = run_gate(repo, base_ref="develop", head_ref="feature")
    assert [f.subject for f in result.fixed] == ["acme.yaml#address"]
    assert result.introduced == []


def test_unknown_ref_and_non_git_are_gate_errors(
    repo: Path, make_repo: MakeRepo
) -> None:
    with pytest.raises(GateError, match="fetch-depth"):
        run_gate(repo, base_ref="nope")
    plain = make_repo(snow=SNOW_DJANGO, files=FILES_ALL_OK, git=False)
    shutil.rmtree(plain / ".git", ignore_errors=True)
    with pytest.raises(GateError, match="not a git repository"):
        run_gate(plain, base_ref="develop")


def test_environment_is_carried_over_only_with_identical_lockfiles(
    repo: Path,
) -> None:
    api = repo / "api"
    (api / "uv.lock").write_text("lock v1\n")
    (api / ".venv").mkdir()
    (api / ".venv" / "marker").write_text("x")
    (repo / ".gitignore").write_text("__pycache__/\n.venv/\n")
    commit(repo, "lock")
    seen: list[bool] = []
    original = run_check

    def spy(root: Path, **kwargs: object) -> Report:
        if root != repo:
            seen.append((root / "api" / ".venv" / "marker").is_file())
        return original(root, **kwargs)  # type: ignore[arg-type]

    import model_wtf.compliance.gate as gate

    gate.run_check = spy  # type: ignore[assignment]
    try:
        result = run_gate(repo, base_ref="develop")
        assert seen == [True]
        assert result.warnings == []
        (api / "uv.lock").write_text("lock v2\n")
        result = run_gate(repo, base_ref="develop")
        assert seen == [True, False]
        assert any("uv.lock differs" in w for w in result.warnings)
    finally:
        gate.run_check = original  # type: ignore[assignment]


def test_cli_requires_merge_into_outside_actions(repo: Path) -> None:
    result = CliRunner().invoke(cli, ["--root", str(repo), "compliance", "ghate"])
    assert result.exit_code == int(ExitCode.TOOL_ERROR)
    assert "--merge-into" in result.output


def test_cli_formats_and_github_context(
    repo: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = CliRunner()
    out = runner.invoke(
        cli,
        [
            "--root",
            str(repo),
            "compliance",
            "ghate",
            "--merge-into",
            "develop",
            "--format",
            "json",
        ],
    )
    assert out.exit_code == 0, out.output
    payload = json.loads(out.output)
    assert payload["introduced"] == []
    assert payload["base"] == "develop"
    assert payload["pre_existing"]

    # Under GitHub Actions: base from the event, annotations, outputs, summary.
    event = tmp_path / "event.json"
    base_sha = git(repo, "rev-parse", "develop")
    event.write_text(json.dumps({"pull_request": {"base": {"sha": base_sha}}}))
    output = tmp_path / "output.txt"
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    context = github_context()
    assert context is not None
    assert context.base_ref == base_sha

    party = repo / "compliance" / "parties" / "acme.yaml"
    party.write_text(party.read_text().replace(ADDRESS, "address: !todo"))
    out = runner.invoke(cli, ["--root", str(repo), "compliance", "ghate"])
    assert out.exit_code == int(ExitCode.FINDINGS), out.output
    assert (
        "::warning file=compliance/parties/acme.yaml,title=todo::acme.yaml#address"
        in out.output
    )
    assert "::notice title=compliance::compliance gate: 1 introduced" in out.output
    assert "introduced=1" in output.read_text()
    assert "| `todo` | 1 |" in summary.read_text()

    # GITHUB_BASE_REF fallback when there is no event file.
    monkeypatch.delenv("GITHUB_EVENT_PATH")
    monkeypatch.setenv("GITHUB_BASE_REF", "develop")
    context = github_context()
    assert context is not None
    assert context.base_ref == "origin/develop"


# ---------------------------------------------------------------------------
# challenges: the deterministic memory behind the challenger
# ---------------------------------------------------------------------------


def test_challenge_reopens_an_item_once_and_a_review_answers_it(repo: Path) -> None:
    from model_wtf.compliance.mcp_server import Decision, Tools

    tools = Tools(repo)
    tools.review_model(
        "api:shop.Customer",
        [Decision(field="email", ok=True), Decision(field="phone", ok=True)],
        "checked",
    )
    commit(repo, "reviews")  # the base has the reviews
    head = git(repo, "rev-parse", "--short", "HEAD")

    # Nothing to challenge on a pending item; a reviewed one goes back to pending.
    assert tools.challenge("api:shop.Customer.iban", "x").startswith("Refused")
    assert tools.challenge(
        "api:shop.Customer.email", "views.py:12 now logs the email"
    ).startswith("Challenged")
    lock = repo / "api" / "compliance" / "data.lock.yaml"
    text = lock.read_text()
    assert "challenge:" in text
    assert f"commit: {head}" in text
    assert "grounds: views.py:12 now logs the email" in text
    _, rows = _rows(repo)
    status = {r.row.id: r.status.value for r in Lock(_rows(repo)[0]).annotate(rows)}
    assert status["shop.Customer.email"] == "pending:challenged"
    assert status["shop.Customer.phone"] == "reviewed"
    # The gate sees it as an introduced finding on exactly that item.
    result = run_gate(repo, base_ref="develop")
    assert [(f.code, f.subject) for f in result.introduced] == [
        ("pending-review", "api:shop.Customer.email")
    ]
    assert "challenged" in result.introduced[0].diagnostic.message

    # No spin: a second challenge is refused while the first is open.
    assert "already challenged" in tools.challenge("api:shop.Customer.email", "again")

    # Re-reviewing answers it; the same grounds at the same commit are refused.
    tools.review_model(
        "api:shop.Customer", [Decision(field="email", ok=True)], "still right"
    )
    text = lock.read_text()
    assert "challenge:" not in text.replace("answered:", "")
    assert "answered:" in text
    assert "already answered" in tools.challenge("api:shop.Customer.email", "again")
    # The reviews tool tells the challenger about it.
    listing = tools.reviews(["api/shop/models.py"])
    assert "api:shop.Customer.email" in listing
    assert "answered challenge at" in listing
    assert "api:shop.Customer.iban" not in listing  # still pending: not an assertion


def test_challenge_on_a_touchpoint_goes_through_the_manifest(repo: Path) -> None:
    from model_wtf.compliance.mcp_server import DataRef, Tools

    tools = Tools(repo)
    assert tools.challenge("api:checkout", "x").startswith("Refused")
    tools.touchpoint_set_data(
        "api:checkout",
        [DataRef(ref="shop.Customer.email", ops=[{"op": "create"}])],
        reason="api.py:22 stores the email",
    )
    commit(repo, "declared")
    listing = tools.reviews(["api/shop/api.py"])
    assert "api:checkout" in listing
    assert "email: create" in listing
    out = tools.challenge("api:checkout", "api.py:30 now mails it to mailgun")
    assert out.startswith("Challenged")
    manifest = repo / "api" / "compliance" / "touchpoints" / "checkout.yaml"
    assert "challenge:" in manifest.read_text()
    result = run_gate(repo, base_ref="develop")
    assert ("touchpoint-pending", "api:checkout") in [
        (f.code, f.subject) for f in result.introduced
    ]
    assert "already challenged" in tools.challenge("api:checkout", "again")
    # Re-declaring answers it.
    tools.touchpoint_set_data(
        "api:checkout",
        [DataRef(ref="shop.Customer.email", ops=[{"op": "create"}])],
        reason="still fine",
    )
    text = manifest.read_text()
    assert "answered:" in text
    assert "\nchallenge:" not in text
    assert "already answered" in tools.challenge("api:checkout", "again")


def test_commit_challenges_stages_only_compliance_files(repo: Path) -> None:
    from model_wtf.compliance.gate import commit_challenges

    (repo / "api" / "shop" / "junk.py").write_text("x = 1\n")
    lock = repo / "api" / "compliance" / "data.lock.yaml"
    lock.write_text("schema: 1\nitems: {}\n")
    sha = commit_challenges(repo, ["api:shop.Customer.email"], base_sha="abc123def456")
    assert sha
    assert "Challenge 1 review(s) after abc123def456" in git(
        repo, "log", "-1", "--format=%s"
    )
    assert git(repo, "status", "--porcelain") == "?? api/shop/junk.py"
    assert commit_challenges(repo, [], base_sha="abc123def456") is None
