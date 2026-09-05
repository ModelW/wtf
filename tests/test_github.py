"""GitHub-facing half: annotations, step summary, PR comment sync."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from declarations_fixtures import RECIPIENT_STRIPE, SNOW_ONE_UNIT, valid_tree
from model_wtf.cli import cli
from model_wtf.compliance.check import run_check
from model_wtf.compliance.github_sync import (
    SUMMARY_MARKER,
    GitHubError,
    IssueComment,
    ReviewComment,
    SyncContext,
    detect_repo_and_pr,
    marker,
    sync_comments,
)
from model_wtf.compliance.init import run_init
from model_wtf.compliance.render import step_summary_markdown

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import MakeRepo

NO_DPA = RECIPIENT_STRIPE.replace("dpa_reference: contracts/stripe-dpa-2024.pdf\n", "")


@dataclass
class FakeGitHub:
    """In-memory PR: records every call, behaves like the real API."""

    files: set[str] = field(default_factory=set)
    reviews: list[ReviewComment] = field(default_factory=list)
    issues: list[IssueComment] = field(default_factory=list)
    resolved: list[str] = field(default_factory=list)
    created_at: list[tuple[str, int, str]] = field(default_factory=list)
    _next: int = 1

    def pr_head_sha(self) -> str:
        return "headsha"

    def pr_files(self) -> set[str]:
        return self.files

    def review_comments(self) -> list[ReviewComment]:
        return list(self.reviews)

    def create_review_comment(
        self, body: str, path: str, line: int, commit_sha: str
    ) -> None:
        self.reviews.append(ReviewComment(self._next, f"node{self._next}", body, path))
        self.created_at.append((path, line, commit_sha))
        self._next += 1

    def update_review_comment(self, comment_id: int, body: str) -> None:
        self.reviews = [
            ReviewComment(c.id, c.node_id, body, c.path) if c.id == comment_id else c
            for c in self.reviews
        ]

    def resolve_thread(self, comment_node_id: str) -> bool:
        self.resolved.append(comment_node_id)
        return True

    def issue_comments(self) -> list[IssueComment]:
        return list(self.issues)

    def create_issue_comment(self, body: str) -> None:
        self.issues.append(IssueComment(self._next, body))
        self._next += 1

    def update_issue_comment(self, comment_id: int, body: str) -> None:
        self.issues = [
            IssueComment(c.id, body) if c.id == comment_id else c for c in self.issues
        ]


@pytest.fixture
def repo_with_findings(make_repo: MakeRepo) -> Path:
    files = valid_tree()
    files["api/compliance/recipients/stripe.yaml"] = NO_DPA
    files["api/compliance/findings/F-0001.yaml"] = files[
        "api/compliance/findings/F-0001.yaml"
    ].split("accepted:")[0]
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)
    run_check(root, strict=False)  # creates F-0002 for the missing DPA
    return root


# ---------------------------------------------------------------------------
# check --format github
# ---------------------------------------------------------------------------


def test_annotation_titles_and_blank_warnings(
    make_repo: MakeRepo, tmp_path: Path
) -> None:
    root = make_repo(snow=SNOW_ONE_UNIT)
    run_init(root, codeowners_team="@a/dpo")
    files = valid_tree()
    files["api/compliance/recipients/stripe.yaml"] = NO_DPA
    for rel, content in files.items():
        if "controller.yaml" in rel:
            continue  # keep init's `open` controller
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(content)
    summary = tmp_path / "summary.md"

    result = CliRunner().invoke(
        cli,
        ["compliance", "check", "--root", str(root), "--format", "github"],
        env={"GITHUB_STEP_SUMMARY": str(summary)},
    )

    assert result.exit_code == 1
    assert (
        "::error file=api/compliance/recipients/stripe.yaml,"
        "title=F-0002 GDPR-PROCESSOR-DPA::" in result.output
    )
    assert "::warning file=api/compliance/controller.yaml,line=2,title=blank::" in (
        result.output
    )
    text = summary.read_text()
    assert text.startswith("## model-wtf compliance check")
    assert "### recipient.stripe" in text
    assert "| finding | GDPR-PROCESSOR-DPA | F-0002 |" in text
    assert "human blank(s)" in text


def test_step_summary_without_env_is_not_written(repo_with_findings: Path) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "compliance",
            "check",
            "--root",
            str(repo_with_findings),
            "--format",
            "github",
        ],
        env={"GITHUB_STEP_SUMMARY": ""},
    )
    assert result.exit_code == 1
    assert "::error" in result.output


def test_step_summary_clean_report(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_ONE_UNIT, files=valid_tree())
    report = run_check(root, strict=False)
    text = step_summary_markdown(report)
    assert "**Verdict:** clean (exit 0)" in text
    assert "Nothing to report." in text


def test_blank_detection_lines(make_repo: MakeRepo) -> None:
    root = make_repo(
        snow=SNOW_ONE_UNIT,
        files={
            **valid_tree(),
            "api/compliance/controller.yaml": (
                "name: open\ncontact:\n  address: 1 rue\n  email: open\n"
            ),
        },
    )
    report = run_check(root, strict=False)
    blanks = [(d.message, d.line) for d in report.diagnostics if d.code == "blank"]
    assert blanks == [
        ("controller.yaml: name is still 'open'", 1),
        ("controller.yaml: contact.email is still 'open'", 4),
    ]


# ---------------------------------------------------------------------------
# gh-sync-comments
# ---------------------------------------------------------------------------


def test_first_sync_creates_comments_and_summary(repo_with_findings: Path) -> None:
    gh = FakeGitHub(
        files={"apps/billing/api.py", "api/compliance/findings/F-0002.yaml"}
    )

    report = sync_comments(repo_with_findings, gh, SyncContext(blanks=0))

    assert report.created == ["F-0001", "F-0002"]
    # F-0001 provenance is in the diff -> anchored on the code line.
    assert ("apps/billing/api.py", 14, "headsha") in gh.created_at
    # F-0002 provenance (stripe.yaml) is not in the diff -> finding file, line 1.
    assert ("api/compliance/findings/F-0002.yaml", 1, "headsha") in gh.created_at
    bodies = [c.body for c in gh.reviews]
    assert any(marker("F-0001") in b and "Unauthenticated POST" in b for b in bodies)
    assert any("add an `accepted:` block" in b for b in bodies)
    assert len(gh.issues) == 1
    assert SUMMARY_MARKER in gh.issues[0].body
    assert "**Open findings:** 2" in gh.issues[0].body
    assert "| F-0002 | high |" in gh.issues[0].body


def test_second_sync_updates_in_place_without_duplicates(
    repo_with_findings: Path,
) -> None:
    gh = FakeGitHub()
    sync_comments(repo_with_findings, gh)
    assert len(gh.reviews) == 2

    second = sync_comments(repo_with_findings, gh)
    assert second.created == []
    assert second.updated == []
    assert len(gh.reviews) == 2
    assert len(gh.issues) == 1

    # Change the finding text: the comment is edited, not re-posted.
    path = repo_with_findings / "api/compliance/findings/F-0001.yaml"
    path.write_text(path.read_text().replace("Unauthenticated POST", "Open POST"))
    third = sync_comments(repo_with_findings, gh)
    assert third.updated == ["F-0001"]
    assert len(gh.reviews) == 2
    assert any("Open POST" in c.body for c in gh.reviews)


def test_deleted_finding_resolves_thread(repo_with_findings: Path) -> None:
    gh = FakeGitHub()
    sync_comments(repo_with_findings, gh)
    (repo_with_findings / "api/compliance/findings/F-0001.yaml").unlink()

    report = sync_comments(repo_with_findings, gh)

    assert report.resolved == ["F-0001"]
    assert gh.resolved == ["node1"]
    resolved = next(c for c in gh.reviews if marker("F-0001") in c.body)
    assert "✅ resolved" in resolved.body
    assert "**Open findings:** 1" in gh.issues[0].body
    # Idempotent: a third run does not resolve again.
    again = sync_comments(repo_with_findings, gh)
    assert again.resolved == []
    assert gh.resolved == ["node1"]


def test_summary_shows_accepted_budget_and_ai(repo_with_findings: Path) -> None:
    path = repo_with_findings / "api/compliance/findings/F-0002.yaml"
    path.write_text(
        path.read_text()
        + "accepted:\n  justification: later\n  review_by: 2030-01-01\n"
    )
    gh = FakeGitHub()

    sync_comments(
        repo_with_findings,
        gh,
        SyncContext(
            blanks=3,
            budget_used="$0.42",
            ai_staged=["GDPR-TRANSFER@recipient:stripe: ai: settings changed"],
        ),
    )

    body = gh.issues[0].body
    assert "**Open findings:** 1" in body
    assert "**Accepted findings:** 1" in body
    assert "**Human blanks (`open`):** 3" in body
    assert "**Agent budget used:** $0.42" in body
    assert "GDPR-TRANSFER@recipient:stripe" in body
    accepted_comment = next(c for c in gh.reviews if marker("F-0002") in c.body)
    assert "✔ accepted: later" in accepted_comment.body


def test_detect_repo_and_pr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "ModelW/wtf")
    monkeypatch.setenv("GITHUB_REF", "refs/pull/42/merge")
    assert detect_repo_and_pr(None, None) == ("ModelW/wtf", 42)
    assert detect_repo_and_pr("x/y", 7) == ("x/y", 7)
    monkeypatch.delenv("GITHUB_REPOSITORY")
    monkeypatch.delenv("GITHUB_REF")
    with pytest.raises(GitHubError, match="--repo"):
        detect_repo_and_pr(None, None)


def test_cli_without_context_exits_4(repo_with_findings: Path) -> None:
    result = CliRunner().invoke(
        cli,
        ["compliance", "gh-sync-comments", "--root", str(repo_with_findings)],
        env={"GITHUB_REPOSITORY": "", "GITHUB_REF": ""},
    )
    assert result.exit_code == 4
