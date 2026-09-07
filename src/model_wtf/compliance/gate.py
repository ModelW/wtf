"""The pull-request gate: a change may not make compliance worse.

Nobody expects a repository to be clean on day one; ``ghate`` (the GitHub
gate) expects it to *not get worse*. It runs the whole ``compliance check``
twice — on the base ref, checked out into a temporary ``git worktree`` with
its own ``compliance/`` state, and on the head (the working tree by
default, so uncommitted work is gated too) — and compares the two sets of
findings by stable identity.

A finding's identity is ``(scope, code, subject)`` — a data id, a
touchpoint id, an activity slug, ``file#field`` for a marker — never a
line number or a message, so rewording a note does not show up as a new
finding. Lines that fold several items (``12 data item(s) pending``) are
compared item by item through :attr:`Diagnostic.items`: a PR that adds an
unreviewed personal field fails, a PR touching an unrelated file while 300
items were already pending does not.

Introspection needs the unit's environment. The worktree gets the head's
``.venv`` / ``node_modules`` linked in when the unit's lockfile is byte
identical on both sides; otherwise the base run is approximate and says
so — a dependency change is a legitimate reason for new findings.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from model_wtf.compliance.check import run_check
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.report import Diagnostic, Report, Section

if TYPE_CHECKING:
    from collections.abc import Iterator

# Per-unit environments worth carrying over to the base worktree, keyed by
# the lockfile that must match for the environment to be the same.
_ENVIRONMENTS: tuple[tuple[str, str], ...] = (
    ("uv.lock", ".venv"),
    ("poetry.lock", ".venv"),
    ("pnpm-lock.yaml", "node_modules"),
    ("package-lock.json", "node_modules"),
    ("yarn.lock", "node_modules"),
)
# Untracked configuration a worktree lacks and introspection needs (Django
# settings read their secrets from it). Copied as-is: settings are not code.
_DOTENV = (".env",)
_GIT_TIMEOUT = 60


class GateError(Exception):
    """The gate could not run (not a git repository, unknown ref, ...)."""


@dataclass(frozen=True, slots=True)
class Finding:
    """One thing the gate compares: a diagnostic, or one item of a fold.

    ``key`` is the identity; ``diagnostic`` is the head's (or base's) line
    it came from so renderers can point at a file and quote the message.
    """

    scope: str
    code: str
    subject: str
    diagnostic: Diagnostic

    @property
    def key(self) -> tuple[str, str, str]:
        """The identity compared between runs."""
        return (self.scope, self.code, self.subject)

    @property
    def section(self) -> Section:
        """The to-do list the finding belongs to."""
        return self.diagnostic.section


def findings_of(report: Report) -> dict[tuple[str, str, str], Finding]:
    """Explode a report into identity-keyed findings.

    Info lines are not findings (nothing to fix). A folded line with
    ``items`` yields one finding per item, keyed on the item id, so the
    fold's own message-only count never counts as a change.
    """
    out: dict[tuple[str, str, str], Finding] = {}
    for diag in report.diagnostics:
        if diag.section is Section.INFO:
            continue
        scope = diag.scope_id or ""
        subjects = diag.items or (diag.subject or _fallback_subject(report, diag),)
        for subject in subjects:
            finding = Finding(scope, diag.code, subject, diag)
            out.setdefault(finding.key, finding)
    return out


def _fallback_subject(report: Report, diag: Diagnostic) -> str:
    """A diagnostic without a subject is identified by its file, then message."""
    if diag.path is not None:
        return report.display_path(diag.path)
    return diag.message


@dataclass
class GateResult:
    """What the gate found: the head report plus the three deltas."""

    base_ref: str
    head: Report
    base: Report | None
    introduced: list[Finding] = field(default_factory=list)
    fixed: list[Finding] = field(default_factory=list)
    pre_existing: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    """Reasons the base run is approximate (environment not carried over)."""

    @property
    def exit_code(self) -> ExitCode:
        """Declaration errors in the head are always the PR's fault; then
        anything introduced fails; pre-existing findings never do."""
        if self.head.by_section()[Section.ERRORS]:
            return ExitCode.DECLARATION_ERROR
        if self.introduced:
            return ExitCode.FINDINGS
        return ExitCode.CLEAN

    def exit_code_with(self, *, fail_on_existing: bool) -> ExitCode:
        """The exit code, with pre-existing findings promoted to failures
        for repositories that are already clean and want to stay so."""
        code = self.exit_code
        if code is ExitCode.CLEAN and fail_on_existing and self.pre_existing:
            return ExitCode.FINDINGS
        return code

    def to_dict(self) -> dict[str, object]:
        """JSON form: the three lists, the warnings, the exit code."""

        def rows(findings: list[Finding]) -> list[dict[str, object]]:
            return [
                {
                    "scope": f.scope,
                    "code": f.code,
                    "subject": f.subject,
                    "section": f.section.value,
                    "message": f.diagnostic.message,
                    "path": self.head.display_path(f.diagnostic.path)
                    if f.diagnostic.path
                    else None,
                    "hint": f.diagnostic.hint,
                }
                for f in findings
            ]

        return {
            "base": self.base_ref,
            "introduced": rows(self.introduced),
            "fixed": rows(self.fixed),
            "pre_existing": rows(self.pre_existing),
            "warnings": list(self.warnings),
            "exit_code": int(self.exit_code),
        }


def compare(head: Report, base: Report, *, base_ref: str) -> GateResult:
    """Diff two reports by finding identity."""
    head_findings = findings_of(head)
    base_findings = findings_of(base)
    result = GateResult(base_ref, head, base)
    for key, finding in sorted(head_findings.items()):
        (result.pre_existing if key in base_findings else result.introduced).append(
            finding
        )
    result.fixed = [
        f for key, f in sorted(base_findings.items()) if key not in head_findings
    ]
    return result


def run_gate(
    root: Path,
    *,
    base_ref: str,
    head_ref: str | None = None,
    strict: bool = False,
    python: str | None = None,
) -> GateResult:
    """Run ``check`` on both sides and compare.

    ``head_ref`` defaults to the working tree as it is; a ref checks that
    revision out into a worktree instead. The base always runs in a
    worktree that is removed afterwards, whatever happens.
    """
    root = root.resolve()
    _ensure_git(root)
    base_sha = _rev_parse(root, base_ref)
    warnings: list[str] = []
    with _worktree(root, base_sha) as base_root:
        warnings.extend(_carry_environments(root, base_root))
        base = run_check(base_root, strict=strict, python=python, allow_todo=True)
        if head_ref is None:
            head = run_check(root, strict=strict, python=python, allow_todo=True)
        else:
            with _worktree(root, _rev_parse(root, head_ref)) as head_root:
                warnings.extend(_carry_environments(root, head_root))
                head = run_check(
                    head_root, strict=strict, python=python, allow_todo=True
                )
    result = compare(head, base, base_ref=base_ref)
    result.warnings = warnings
    return result


# ---------------------------------------------------------------------------
# git
# ---------------------------------------------------------------------------


def _git(root: Path, *args: str) -> str:
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, our own arguments
            ["git", *args],  # noqa: S607 - git from PATH is the point
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=_GIT_TIMEOUT,
        )
    except FileNotFoundError as exc:
        msg = "git is not installed"
        raise GateError(msg) from exc
    except subprocess.TimeoutExpired as exc:
        msg = f"git {args[0]} timed out"
        raise GateError(msg) from exc
    if proc.returncode != 0:
        msg = f"git {' '.join(args)}: {proc.stderr.strip()}"
        raise GateError(msg)
    return proc.stdout.strip()


def _ensure_git(root: Path) -> None:
    if not (root / ".git").exists():
        msg = f"{root} is not a git repository"
        raise GateError(msg)


def _rev_parse(root: Path, ref: str) -> str:
    try:
        return _git(root, "rev-parse", "--verify", f"{ref}^{{commit}}")
    except GateError as exc:
        msg = (
            f"unknown ref {ref!r}; in CI, check out with `fetch-depth: 0` "
            f"so the base branch is available ({exc})"
        )
        raise GateError(msg) from exc


class _worktree:
    """``git worktree add --detach`` into a temp folder, removed on exit."""

    def __init__(self, root: Path, sha: str) -> None:
        self.root = root
        self.sha = sha
        # Inside .git so nothing lands in the tree; the env override is for
        # tests, or a repo whose .git is somewhere odd.
        default = _git(root, "rev-parse", "--git-common-dir")
        base = Path(os.environ.get("MODEL_WTF_WORKTREE_DIR", default))
        if not base.is_absolute():
            base = root / base
        self.path = base / "model-wtf" / f"gate-{sha[:12]}"

    def __enter__(self) -> Path:
        if self.path.exists():
            self._remove()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _git(self.root, "worktree", "add", "--detach", str(self.path), self.sha)
        return self.path

    def __exit__(self, *exc: object) -> None:
        self._remove()

    def _remove(self) -> None:
        try:
            _git(self.root, "worktree", "remove", "--force", str(self.path))
        except GateError:
            shutil.rmtree(self.path, ignore_errors=True)
            try:
                _git(self.root, "worktree", "prune")
            except GateError:
                pass


def _carry_environments(head_root: Path, other_root: Path) -> list[str]:
    """Link each unit's ``.venv`` / ``node_modules`` into the worktree.

    Only when the lockfile next to it is byte identical: a different lock
    means a different environment, and running the base against the head's
    packages could invent or hide findings. Then the base is approximate
    and the caller says so.
    """
    warnings: list[str] = []
    for name in _DOTENV:
        for dotenv in _lockfiles(head_root, name):
            target = other_root / dotenv.relative_to(head_root)
            if not target.exists():
                shutil.copy2(dotenv, target)
    for lock, env_dir in _ENVIRONMENTS:
        for head_lock in _lockfiles(head_root, lock):
            warning = _carry_one(head_root, other_root, head_lock, lock, env_dir)
            if warning:
                warnings.append(warning)
    return warnings


def _carry_one(
    head_root: Path, other_root: Path, head_lock: Path, lock: str, env_dir: str
) -> str | None:
    """Link the environments one lockfile covers; a reason when it cannot.

    A workspace lockfile at the root covers the packages below it (pnpm and
    uv workspaces), so their environments are linked too.
    """
    rel = head_lock.relative_to(head_root)
    base_lock = other_root / rel
    envs = [
        folder / env_dir
        for folder in (head_lock.parent, *_children(head_lock.parent))
        if (folder / env_dir).is_dir()
    ]
    if not envs:
        return None
    if not base_lock.is_file():
        return (
            f"{rel.parent}: {lock} does not exist on the base; its "
            f"{env_dir} was not carried over"
        )
    if head_lock.read_bytes() != base_lock.read_bytes():
        return (
            f"{rel.parent}: {lock} differs between base and head; the "
            f"base ran without {env_dir} (findings there are approximate)"
        )
    for env in envs:
        target = other_root / env.relative_to(head_root)
        if not target.exists() and target.parent.is_dir():
            target.symlink_to(env, target_is_directory=True)
    return None


def _children(folder: Path) -> Iterator[Path]:
    for child in sorted(folder.iterdir()):
        if (
            child.is_dir()
            and not child.name.startswith(".")
            and child.name != "node_modules"
        ):
            yield child


def _lockfiles(root: Path, name: str) -> Iterator[Path]:
    """Files named ``name`` at the root or one folder down, skipping environments."""
    if (root / name).is_file():
        yield root / name
    for child in sorted(root.iterdir()):
        if child.name.startswith(".") or child.name == "node_modules":
            continue
        if child.is_dir() and (child / name).is_file():
            yield child / name


# ---------------------------------------------------------------------------
# GitHub Actions context
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GitHubContext:
    """What the workflow tells us about the pull request."""

    base_ref: str
    head_ref: str | None
    output_path: Path | None
    summary_path: Path | None


def github_context() -> GitHubContext | None:
    """Read the pull request from the Actions environment, if we are in one.

    ``GITHUB_EVENT_PATH`` holds the event; its ``pull_request.base.sha``
    is the exact base (``GITHUB_BASE_REF`` is only the branch name and needs
    ``origin/`` in front). The head is the checked-out tree, so no ref.
    """
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return None
    base: str | None = None
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path and Path(event_path).is_file():
        try:
            event = json.loads(Path(event_path).read_text())
            base = event.get("pull_request", {}).get("base", {}).get("sha")
        except (json.JSONDecodeError, AttributeError):
            base = None
    if base is None and os.environ.get("GITHUB_BASE_REF"):
        base = f"origin/{os.environ['GITHUB_BASE_REF']}"
    if base is None:
        return None
    return GitHubContext(
        base_ref=base,
        head_ref=None,
        output_path=_env_path("GITHUB_OUTPUT"),
        summary_path=_env_path("GITHUB_STEP_SUMMARY"),
    )


def _env_path(name: str) -> Path | None:
    value = os.environ.get(name)
    return Path(value) if value else None


def write_github_outputs(result: GateResult, context: GitHubContext) -> None:
    """``introduced`` / ``fixed`` / ``pre_existing`` counts as step outputs,
    and a Markdown table in the step summary."""
    if context.output_path is not None:
        with context.output_path.open("a") as fh:
            fh.write(f"introduced={len(result.introduced)}\n")
            fh.write(f"fixed={len(result.fixed)}\n")
            fh.write(f"pre-existing={len(result.pre_existing)}\n")
    if context.summary_path is not None:
        with context.summary_path.open("a") as fh:
            fh.write(summary_markdown(result))


def summary_markdown(result: GateResult) -> str:
    """The step summary: verdict, then a table per check code."""
    lines = ["## Compliance gate", ""]
    if result.exit_code is ExitCode.DECLARATION_ERROR:
        lines.append("**Declaration errors** in this branch — fix the files.")
    elif result.introduced:
        lines.append(
            f"**{len(result.introduced)} finding(s) introduced** by this change."
        )
    else:
        lines.append("Nothing introduced.")
    if result.fixed:
        lines.append(f"{len(result.fixed)} fixed. ")
    lines += [
        "",
        "| Check | Introduced | Fixed | Pre-existing |",
        "| -- | --: | --: | --: |",
    ]
    codes = sorted(
        {f.code for f in result.introduced + result.fixed + result.pre_existing}
    )
    for code in codes:
        counts = [
            sum(1 for f in bucket if f.code == code)
            for bucket in (result.introduced, result.fixed, result.pre_existing)
        ]
        lines.append(f"| `{code}` | {counts[0]} | {counts[1]} | {counts[2]} |")
    if result.introduced:
        lines += ["", "### Introduced", ""]
        lines += [
            f"- `{f.scope}` **{f.code}** {f.subject} — {f.diagnostic.message}"
            for f in result.introduced
        ]
    if result.warnings:
        lines += ["", "### Approximate base", ""]
        lines += [f"- {w}" for w in result.warnings]
    return "\n".join(lines) + "\n"


__all__ = [
    "Finding",
    "GateError",
    "GateResult",
    "GitHubContext",
    "compare",
    "findings_of",
    "github_context",
    "run_gate",
    "summary_markdown",
    "write_github_outputs",
]
