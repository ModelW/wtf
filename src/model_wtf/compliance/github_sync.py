"""``compliance gh-sync-comments``: mirror ``findings/`` onto a pull request.

One review comment per finding, anchored at its provenance when that file
is part of the PR diff (else on the finding file the bot committed), each
carrying a ``<!-- model-wtf F-NNNN -->`` marker so re-runs update in place
instead of piling up. When a finding disappears, its thread is resolved.
One summary comment is edited in place across runs.

GitHub is reached through ``gh api`` (already authenticated in Actions via
``GITHUB_TOKEN``); the transport is a small protocol so tests use a fake.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

from model_wtf.compliance.check import SHARED_FOLDER
from model_wtf.compliance.discovery import load_units, select_manifest
from model_wtf.compliance.ledger import LedgerStore
from model_wtf.compliance.report import DeclarationError

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

    from model_wtf.compliance.declarations.schemas import Finding

MARKER_RE = re.compile(r"<!-- model-wtf (F-\d{4,}) -->")
SUMMARY_MARKER = "<!-- model-wtf summary -->"


def marker(finding_id: str) -> str:
    """The HTML comment that ties a PR comment to a finding."""
    return f"<!-- model-wtf {finding_id} -->"


class GitHubError(Exception):
    """A GitHub call failed."""


@dataclass(frozen=True, slots=True)
class ReviewComment:
    """An existing inline review comment on the PR."""

    id: int
    node_id: str
    body: str
    path: str


@dataclass(frozen=True, slots=True)
class IssueComment:
    """An existing top-level (conversation) comment on the PR."""

    id: int
    body: str


class GitHubClient(Protocol):
    """The handful of GitHub operations the sync needs."""

    def pr_head_sha(self) -> str:
        """SHA the review comments should be anchored to."""
        ...

    def pr_files(self) -> set[str]:
        """Paths touched by the PR (for provenance anchoring)."""
        ...

    def review_comments(self) -> list[ReviewComment]:
        """Inline review comments on the PR."""
        ...

    def create_review_comment(
        self, body: str, path: str, line: int, commit_sha: str
    ) -> None:
        """Post an inline comment on ``path:line`` at ``commit_sha``."""
        ...

    def update_review_comment(self, comment_id: int, body: str) -> None:
        """Edit an inline comment in place."""
        ...

    def resolve_thread(self, comment_node_id: str) -> bool:
        """Resolve the review thread holding the comment; ``False`` if not found."""
        ...

    def issue_comments(self) -> list[IssueComment]:
        """Conversation comments on the PR."""
        ...

    def create_issue_comment(self, body: str) -> None:
        """Post a conversation comment."""
        ...

    def update_issue_comment(self, comment_id: int, body: str) -> None:
        """Edit a conversation comment."""
        ...


@dataclass(slots=True)
class SyncReport:
    """What the sync did, for the step log."""

    created: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    resolved: list[str] = field(default_factory=list)
    summary: str = ""


@dataclass(frozen=True, slots=True)
class SyncContext:
    """Extra facts the summary comment shows (filled by the workflow)."""

    blanks: int = 0
    budget_used: str | None = None
    ai_staged: Iterable[str] = ()


# ---------------------------------------------------------------------------
# Sync
# ---------------------------------------------------------------------------


def sync_comments(
    root: Path, client: GitHubClient, context: SyncContext | None = None
) -> SyncReport:
    """Make the PR's comments agree with the ``findings/`` on disk."""
    context = context or SyncContext()
    report = SyncReport()
    findings = _all_findings(root)
    existing = {
        m.group(1): comment
        for comment in client.review_comments()
        if (m := MARKER_RE.search(comment.body))
    }
    head = client.pr_head_sha()
    pr_files = client.pr_files()

    for finding_id, (rel_path, finding) in sorted(findings.items()):
        body = finding_body(finding_id, finding, rel_path)
        if finding_id in existing:
            if existing[finding_id].body != body:
                client.update_review_comment(existing[finding_id].id, body)
                report.updated.append(finding_id)
            continue
        path, line = _anchor(finding, rel_path, pr_files)
        client.create_review_comment(body, path, line, head)
        report.created.append(finding_id)

    for finding_id, comment in sorted(existing.items()):
        if finding_id not in findings and "✅ resolved" not in comment.body:
            resolved = client.resolve_thread(comment.node_id)
            client.update_review_comment(
                comment.id,
                comment.body + "\n\n✅ resolved: the finding no longer exists.",
            )
            report.resolved.append(
                finding_id + ("" if resolved else " (thread not found)")
            )

    report.summary = summary_body(findings, context)
    summaries = [c for c in client.issue_comments() if SUMMARY_MARKER in c.body]
    if summaries:
        if summaries[0].body != report.summary:
            client.update_issue_comment(summaries[0].id, report.summary)
    else:
        client.create_issue_comment(report.summary)
    return report


def _all_findings(root: Path) -> dict[str, tuple[str, Finding]]:
    """``F-NNNN -> (repo-relative finding path, Finding)`` across every unit."""
    folders = [root / SHARED_FOLDER]
    try:
        units, _ = load_units(select_manifest(root), root, strict=False)
        folders.extend(u.folder for u in units)
    except DeclarationError:
        pass
    out: dict[str, tuple[str, Finding]] = {}
    seen: set[Path] = set()
    for folder in folders:
        if folder.resolve() in seen:
            continue
        seen.add(folder.resolve())
        store = LedgerStore(folder)
        for finding_id, finding in store.all_findings().items():
            rel = store.finding_path(finding_id).resolve().relative_to(root.resolve())
            out[finding_id] = (rel.as_posix(), finding)
    return out


def _anchor(finding: Finding, rel_path: str, pr_files: set[str]) -> tuple[str, int]:
    """Provenance ``path:line`` when in the diff, else line 1 of the finding file."""
    for entry in finding.provenance:
        path, _, line = entry.rpartition(":")
        if not path or not line.isdigit():
            path, line = entry, "1"
        if path in pr_files:
            return path, int(line)
    return rel_path, 1


def finding_body(finding_id: str, finding: Finding, rel_path: str) -> str:
    """The review comment for one finding."""
    lines = [
        marker(finding_id),
        f"**{finding_id} · {finding.summary}**",
        "",
        f"`{finding.checkpoint}` · severity **{finding.severity}**",
        "",
        finding.detail.strip(),
        "",
        "**Remediation**",
        "",
        finding.remediation.strip(),
        "",
        f"Finding file: `{rel_path}` -- fix the code, or add an `accepted:` block "
        "there (justification + `review_by`) to accept the risk.",
    ]
    if finding.references:
        lines.append(f"References: {', '.join(finding.references)}")
    if finding.accepted:
        lines.append("")
        lines.append(
            f"✔ accepted: {finding.accepted.justification} "
            f"(review by {finding.accepted.review_by.isoformat()})"
        )
    return "\n".join(lines)


def summary_body(findings: dict[str, tuple[str, Finding]], context: SyncContext) -> str:
    """The single, edited-in-place conversation comment."""
    open_ = {k: v for k, v in findings.items() if v[1].accepted is None}
    accepted = {k: v for k, v in findings.items() if v[1].accepted is not None}
    lines = [
        SUMMARY_MARKER,
        "## model-wtf compliance",
        "",
        f"- **Open findings:** {len(open_)}",
        f"- **Accepted findings:** {len(accepted)}",
        f"- **Human blanks (`open`):** {context.blanks}",
    ]
    if context.budget_used is not None:
        lines.append(f"- **Agent budget used:** {context.budget_used}")
    ai_staged = list(context.ai_staged)
    if ai_staged:
        lines.append(f"- **Re-staged by the agent:** {len(ai_staged)}")
    lines.append("")
    if open_:
        lines.append("| Finding | Severity | Checkpoint | Summary |")
        lines.append("| --- | --- | --- | --- |")
        for finding_id, (_, finding) in sorted(open_.items()):
            lines.append(
                f"| {finding_id} | {finding.severity} | `{finding.checkpoint}` | "
                f"{finding.summary.replace('|', '/')} |"
            )
        lines.append("")
    if ai_staged:
        lines.append("<details><summary>Checkpoints re-staged by the agent</summary>")
        lines.append("")
        lines.extend(f"- {item}" for item in ai_staged)
        lines.append("")
        lines.append("</details>")
        lines.append("")
    lines.append(
        "**How to resolve:** fix the code (the finding disappears on the next "
        "push), or accept the risk by adding to the finding file:\n\n"
        "```yaml\naccepted:\n  justification: why this is fine here\n"
        "  review_by: 2027-01-01\n```\n\n"
        "CODEOWNERS pulls the DPO/CISO in on any change under `compliance/`."
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# gh-backed client
# ---------------------------------------------------------------------------


class GhClient:
    """:class:`GitHubClient` implemented with the ``gh`` CLI."""

    def __init__(self, repo: str, pr: int) -> None:
        self.repo = repo
        self.pr = pr

    def _api(
        self, *args: str, method: str = "GET", payload: dict[str, Any] | None = None
    ) -> Any:
        cmd = ["gh", "api", "--method", method, *args]
        if payload is not None:
            cmd += ["--input", "-"]
        try:
            result = subprocess.run(  # noqa: S603 - fixed argv
                cmd,
                input=json.dumps(payload) if payload is not None else None,
                capture_output=True,
                text=True,
                check=True,
                timeout=120,
            )
        except subprocess.CalledProcessError as exc:
            msg = f"gh api {' '.join(args)}: {exc.stderr.strip()}"
            raise GitHubError(msg) from exc
        except (OSError, subprocess.SubprocessError) as exc:
            msg = f"gh api {' '.join(args)}: {exc}"
            raise GitHubError(msg) from exc
        return json.loads(result.stdout) if result.stdout.strip() else None

    def _paginated(self, path: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        page = 1
        while True:
            batch = self._api(f"{path}?per_page=100&page={page}") or []
            out.extend(batch)
            if len(batch) < 100:
                return out
            page += 1

    def pr_head_sha(self) -> str:
        """SHA of the PR head."""
        data = self._api(f"repos/{self.repo}/pulls/{self.pr}")
        return str(data["head"]["sha"])

    def pr_files(self) -> set[str]:
        """Paths in the PR diff."""
        return {
            f["filename"]
            for f in self._paginated(f"repos/{self.repo}/pulls/{self.pr}/files")
        }

    def review_comments(self) -> list[ReviewComment]:
        """Inline review comments."""
        return [
            ReviewComment(c["id"], c["node_id"], c.get("body", ""), c.get("path", ""))
            for c in self._paginated(f"repos/{self.repo}/pulls/{self.pr}/comments")
        ]

    def create_review_comment(
        self, body: str, path: str, line: int, commit_sha: str
    ) -> None:
        """Post an inline comment."""
        self._api(
            f"repos/{self.repo}/pulls/{self.pr}/comments",
            method="POST",
            payload={
                "body": body,
                "path": path,
                "line": line,
                "commit_id": commit_sha,
                "side": "RIGHT",
            },
        )

    def update_review_comment(self, comment_id: int, body: str) -> None:
        """Edit an inline comment."""
        self._api(
            f"repos/{self.repo}/pulls/comments/{comment_id}",
            method="PATCH",
            payload={"body": body},
        )

    def resolve_thread(self, comment_node_id: str) -> bool:
        """Resolve via GraphQL (REST cannot resolve threads)."""
        owner, name = self.repo.split("/", 1)
        query = (
            "query($owner:String!,$name:String!,$pr:Int!){repository(owner:$owner,name:$name)"
            "{pullRequest(number:$pr){reviewThreads(first:100){nodes{id isResolved "
            "comments(first:1){nodes{id}}}}}}}"
        )
        data = self._api(
            "graphql",
            method="POST",
            payload={
                "query": query,
                "variables": {"owner": owner, "name": name, "pr": self.pr},
            },
        )
        threads = data["data"]["repository"]["pullRequest"]["reviewThreads"]["nodes"]
        for thread in threads:
            first = thread["comments"]["nodes"]
            if first and first[0]["id"] == comment_node_id:
                if not thread["isResolved"]:
                    self._api(
                        "graphql",
                        method="POST",
                        payload={
                            "query": (
                                "mutation($id:ID!){resolveReviewThread"
                                "(input:{threadId:$id}){thread{id}}}"
                            ),
                            "variables": {"id": thread["id"]},
                        },
                    )
                return True
        return False

    def issue_comments(self) -> list[IssueComment]:
        """Conversation comments."""
        return [
            IssueComment(c["id"], c.get("body", ""))
            for c in self._paginated(f"repos/{self.repo}/issues/{self.pr}/comments")
        ]

    def create_issue_comment(self, body: str) -> None:
        """Post a conversation comment."""
        self._api(
            f"repos/{self.repo}/issues/{self.pr}/comments",
            method="POST",
            payload={"body": body},
        )

    def update_issue_comment(self, comment_id: int, body: str) -> None:
        """Edit a conversation comment."""
        self._api(
            f"repos/{self.repo}/issues/comments/{comment_id}",
            method="PATCH",
            payload={"body": body},
        )


def detect_repo_and_pr(repo: str | None, pr: int | None) -> tuple[str, int]:
    """Fill ``repo``/``pr`` from the Actions environment when omitted."""
    repo = repo or os.environ.get("GITHUB_REPOSITORY")
    if pr is None:
        ref = os.environ.get("GITHUB_REF", "")
        match = re.match(r"refs/pull/(\d+)/", ref)
        pr = int(match.group(1)) if match else None
    if not repo or pr is None:
        msg = "cannot determine repository/PR: pass --repo and --pr (or run in Actions)"
        raise GitHubError(msg)
    return repo, pr
