"""Data model of a ``compliance check`` run.

The check itself is a pure function producing a :class:`Report`; the CLI
only renders it. Keeping the model free of any I/O or console concern is
what lets the three output formats (and the tests) share one source of
truth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from model_wtf.compliance.exit_codes import ExitCode

if TYPE_CHECKING:
    from pathlib import Path


class Severity(StrEnum):
    """How bad a diagnostic is.

    ``ERROR`` and ``FINDING`` influence the exit code; ``WARNING`` is
    informational.
    ``--strict`` works by promoting specific warnings to errors at emission
    time, so renderers never need to know about strictness.
    """

    WARNING = "warning"
    ERROR = "error"
    FINDING = "finding"
    """An open finding (failed gate, agent ``not_ok``). Maps to exit 1, which
    ``ERROR`` (exit 3) outranks."""


class ScopeKind(StrEnum):
    """Where a compliance folder comes from."""

    SHARED = "shared"
    """The repo-root ``compliance/`` folder (controller, actors, ...)."""

    UNIT = "unit"
    """A per-image folder declared in the manifest."""


class ScopeStatus(StrEnum):
    """Filesystem state of a scope's folder."""

    OK = "ok"
    EMPTY = "empty"
    MISSING = "missing"


@dataclass(frozen=True, slots=True)
class Diagnostic:
    """One thing worth telling the user about.

    Parameters
    ----------
    severity
        Whether this affects the exit code.
    code
        Stable machine-readable identifier (``kebab-case``) so CI or a
        review bot can match on it without parsing the message.
    message
        Human-readable explanation.
    scope_id
        The unit/scope this is about, if any.
    path
        File or folder the diagnostic points at, if any. Used by the
        GitHub renderer to attach the annotation to a file.
    line
        1-based line inside ``path`` when the problem is located inside a
        file (a bad YAML key, an unknown reference), else ``None``.
    element
        The element file id (``recipient.stripe``) for checkpoint-related
        diagnostics, so summaries can group by element.
    finding_id
        The ``F-NNNN`` behind an open-finding diagnostic; goes into the
        GitHub annotation title.
    """

    severity: Severity
    code: str
    message: str
    scope_id: str | None = None
    path: Path | None = None
    line: int | None = None
    element: str | None = None
    finding_id: str | None = None

    @property
    def title(self) -> str:
        """Annotation title: ``F-NNNN RULE`` for findings, else the code."""
        return f"{self.finding_id} {self.code}" if self.finding_id else self.code

    @property
    def location(self) -> str | None:
        """``path:line`` (or just ``path``) for messages, ``None`` if pathless."""
        if self.path is None:
            return None
        return f"{self.path}:{self.line}" if self.line else str(self.path)


@dataclass(frozen=True, slots=True)
class Unit:
    """A compliance unit declared in the manifest.

    Parameters
    ----------
    id
        The image / unit identifier (``api``, ``front``, ...).
    folder
        Absolute path to the unit's compliance folder.
    """

    id: str
    folder: Path


@dataclass(frozen=True, slots=True)
class Scope:
    """A compliance folder that was inspected.

    Parameters
    ----------
    id
        ``shared`` for the repo-root folder, else the unit id.
    kind
        Shared or unit scope.
    path
        Absolute path to the folder.
    exists
        Whether the folder is present on disk.
    file_count
        Number of non-hidden regular files found recursively. Zero when
        the folder is missing.
    """

    id: str
    kind: ScopeKind
    path: Path
    exists: bool
    file_count: int

    @property
    def status(self) -> ScopeStatus:
        """Collapse ``exists`` and ``file_count`` into one displayable state."""
        if not self.exists:
            return ScopeStatus.MISSING
        if self.file_count == 0:
            return ScopeStatus.EMPTY
        return ScopeStatus.OK


class DeclarationError(Exception):
    """A problem in the declarations that stops the check from proceeding.

    Raised by the discovery layer (missing or malformed manifest); caught by
    :func:`model_wtf.compliance.check.run_check` and turned into a report
    with :attr:`ExitCode.DECLARATION_ERROR`. It carries a ready-made
    :class:`Diagnostic` so the caller has nothing to reformat.
    """

    def __init__(self, diagnostic: Diagnostic) -> None:
        super().__init__(diagnostic.message)
        self.diagnostic = diagnostic


@dataclass(frozen=True, slots=True)
class Report:
    """Complete outcome of one ``compliance check`` run.

    Parameters
    ----------
    root
        The repository root the check ran against (resolved).
    manifest
        The manifest that was used for unit discovery, or ``None`` if none
        could be selected.
    scopes
        Inspected folders, shared scope first, then units in manifest
        order.
    diagnostics
        Warnings and errors, in emission order.
    exit_code
        The process exit code this report maps to.
    """

    root: Path
    manifest: Path | None
    scopes: tuple[Scope, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = field(default_factory=tuple)
    exit_code: ExitCode = ExitCode.CLEAN

    def display_path(self, path: Path) -> str:
        """Render ``path`` relative to the root when possible.

        Absolute paths are noise in a CI log and unstable in test
        fixtures; anything outside the root (should not happen, but a
        manifest may point anywhere) falls back to the absolute form.
        """
        try:
            rel = path.relative_to(self.root)
        except ValueError:
            return str(path)
        return str(rel) if str(rel) != "." else "."

    def to_dict(self) -> dict[str, Any]:
        """Serialise for ``--format json``.

        Paths are emitted relative to the root so the output is stable
        across machines and checkouts.
        """
        return {
            "root": str(self.root),
            "manifest": self.display_path(self.manifest) if self.manifest else None,
            "scopes": [
                {
                    "id": scope.id,
                    "kind": scope.kind.value,
                    "path": self.display_path(scope.path),
                    "exists": scope.exists,
                    "file_count": scope.file_count,
                    "status": scope.status.value,
                }
                for scope in self.scopes
            ],
            "diagnostics": [
                {
                    "severity": diag.severity.value,
                    "code": diag.code,
                    "message": diag.message,
                    "scope": diag.scope_id,
                    "path": self.display_path(diag.path) if diag.path else None,
                    "line": diag.line,
                    "element": diag.element,
                    "finding": diag.finding_id,
                }
                for diag in self.diagnostics
            ],
            "exit_code": int(self.exit_code),
        }
