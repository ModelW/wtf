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
from model_wtf.compliance.yaml_io import (
    Marker,
    Missing,
    field_description,
    iter_markers,
)

if TYPE_CHECKING:
    from pathlib import Path

    from pydantic import BaseModel


class Severity(StrEnum):
    """How bad a diagnostic is.

    Only ``ERROR`` influences the exit code; ``WARNING`` is informational.
    ``--strict`` works by promoting specific warnings to errors at emission
    time, so renderers never need to know about strictness.
    """

    INFO = "info"
    """Worth knowing, never a finding. Warnings here print by default;
    ``Severity.INFO`` entries only with ``--verbose``."""

    WARNING = "warning"
    ERROR = "error"


class ScopeKind(StrEnum):
    """Where a compliance folder comes from."""

    SHARED = "shared"
    """The repo-root ``compliance/`` folder (controller, actors, ...)."""

    UNIT = "unit"
    """A per-image folder declared in the manifest."""


class ScopeStatus(StrEnum):
    """Outcome of a scope, worst diagnostic wins."""

    OK = "ok"
    """Folder present, nothing owed."""

    PENDING = "pending"
    """Folder present; ``!todo``/``!missing`` values or unreviewed items remain."""

    ERROR = "error"
    """Invalid declarations, or the folder is missing (``init`` not run)."""


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
    subject
        Stable identifier of *what* the diagnostic is about: a data id, a
        touchpoint id, an activity slug, or ``file#field`` for a marker.
        This is what a gate diffs between two runs; the message is free to
        change wording, the subject is not.
    hint
        The command or action that resolves it (``data auto-review``); the
        text renderer prints it after an arrow.
    note
        Free text attached by whoever wrote the finding (the marker's note,
        an agent's justification); kept apart from the message so renderers
        can fold lines without losing it.
    origin
        Who established a Missing finding: ``derived`` (the tool, from ops
        and exemptions), ``claimed`` (an agent that read the code),
        ``declared`` (a human's ``!missing``).
    items
        For a line that folds several things (``12 data item(s) pending``),
        their stable ids. The text renderer keeps the fold; JSON and the
        gate see each item, so a PR is judged on the items it adds.
    risk
        For a weighed threat finding: ``critical`` … ``info``. Renderers
        sort on it and tag the line; the gate carries it through.
    """

    severity: Severity
    code: str
    message: str
    scope_id: str | None = None
    path: Path | None = None
    subject: str | None = None
    hint: str | None = None
    note: str | None = None
    origin: str | None = None
    items: tuple[str, ...] = ()
    risk: str | None = None

    @property
    def section(self) -> Section:
        """Which to-do list this belongs to; see :class:`Section`."""
        if self.severity is Severity.ERROR:
            return Section.ERRORS
        if self.severity is Severity.INFO:
            return Section.INFO
        if self.code in MISSING_CODES or self.code.endswith("-missing"):
            return Section.MISSING
        if self.code == "todo":
            return Section.TODO
        if self.code in REVIEW_CODES:
            return Section.REVIEW
        # Any other warning is an advisory (unit not introspectable, image
        # without a compliance block outside --strict): worth printing,
        # nothing to do about it from a compliance standpoint.
        return Section.INFO


MISSING_CODES = frozenset({"missing", "no-pii-violated", "threat-missing"})
"""Codes of the Missing section besides the ``*-missing`` family."""

REVIEW_CODES = frozenset(
    {
        "pending-review",
        "touchpoint-pending",
        "touchpoint-orphan",
        "touchpoint-stale-form",
        "manual-exemption",
        "threat-open",
    }
)
"""Warning codes that ask for a review round and fail the check."""


class Section(StrEnum):
    """The kind of work a diagnostic asks for.

    ``check`` is a to-do list: it groups findings by what has to happen
    next rather than by severity, and the exit code follows the sections.
    """

    ERRORS = "errors"
    """The files are wrong; fix them (exit 3)."""

    MISSING = "missing"
    """A non-compliance is established: code or process to build (exit 1,
    never ignorable)."""

    TODO = "todo"
    """A question only a human can answer (exit 1; ``--allow-todo`` → 0)."""

    REVIEW = "review"
    """Run the agents, or decide (exit 1)."""

    INFO = "info"
    """Worth knowing, never a finding. Warnings here print by default;
    ``Severity.INFO`` entries only with ``--verbose``."""


@dataclass(frozen=True, slots=True)
class Unit:
    """A compliance unit declared in the manifest.

    Parameters
    ----------
    id
        The image / unit identifier (``api``, ``front``, ...).
    folder
        Absolute path to the unit's compliance folder.
    discover
        Discovery engine declared for the unit (``django``, ``sveltekit``,
        ``none``).
    code_root
        Where the unit's code lives (the Dockerfile's folder); the folder
        extractors are run against.
    """

    id: str
    folder: Path
    discover: str = "none"
    code_root: Path | None = None


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
        Whether the folder is present on disk. A folder with no files is a
        legitimate state (everything rule-classified and reviewed); a
        missing one means ``init`` was never run for this scope.
    items
        Data items inventoried for a unit scope (``None`` for the shared
        scope, which has no inventory).
    errors, missing, todos, pending
        Counts of the diagnostics attributed to this scope, by section
        (``pending`` is the Review section).
    """

    id: str
    kind: ScopeKind
    path: Path
    exists: bool
    items: int | None = None
    errors: int = 0
    missing: int = 0
    todos: int = 0
    pending: int = 0

    @property
    def status(self) -> ScopeStatus:
        """Worst thing wrong with this scope."""
        if not self.exists or self.errors:
            return ScopeStatus.ERROR
        if self.missing or self.todos or self.pending:
            return ScopeStatus.PENDING
        return ScopeStatus.OK


def _marker_origin(marker: Marker) -> str:
    """``claimed`` when an agent wrote the marker, ``declared`` otherwise."""
    return (
        "claimed" if (marker.note or "").lstrip().startswith("[agent]") else "declared"
    )


def marker_diagnostics(
    model: BaseModel, path: Path, scope_id: str | None
) -> list[Diagnostic]:
    """One diagnostic per ``!todo`` / ``!missing`` value inside ``model``.

    Todos land in the Todo section (code ``todo``), missings in the Missing
    section (code ``missing``). The subject is ``<file>#<dotted field>`` so a
    gate can tell "the same open question" across runs; a note is appended
    to the message when present.
    """
    out: list[Diagnostic] = []
    for dotted, marker in iter_markers(model):
        missing = isinstance(marker, Missing)
        message = f"{path.name}: {dotted} is {marker.tag}"
        if marker.note:
            message += f' "{marker.note}"'
        out.append(
            Diagnostic(
                Severity.WARNING,
                "missing" if missing else "todo",
                message,
                scope_id,
                path,
                subject=f"{path.name}#{dotted}",
                # For a todo the hint is the question the field asks; the
                # ``--todo`` questionnaire is built from it.
                hint=None if missing else field_description(model, dotted),
                note=marker.note,
                origin=_marker_origin(marker) if missing else None,
            )
        )
    return out


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
                    "items": scope.items,
                    "errors": scope.errors,
                    "missing": scope.missing,
                    "todos": scope.todos,
                    "pending": scope.pending,
                    "status": scope.status.value,
                }
                for scope in self.scopes
            ],
            "diagnostics": [self._diag_dict(d) for d in self.diagnostics],
            "sections": {
                section.value: [
                    self._diag_dict(d) for d in self.diagnostics if d.section is section
                ]
                for section in Section
            },
            "exit_code": int(self.exit_code),
        }

    def _diag_dict(self, diag: Diagnostic) -> dict[str, Any]:
        return {
            "severity": diag.severity.value,
            "section": diag.section.value,
            "code": diag.code,
            "message": diag.message,
            "scope": diag.scope_id,
            "path": self.display_path(diag.path) if diag.path else None,
            "subject": diag.subject,
            "hint": diag.hint,
            "note": diag.note,
            "origin": diag.origin,
            "items": list(diag.items),
            "risk": diag.risk,
        }

    def by_section(self) -> dict[Section, list[Diagnostic]]:
        """Diagnostics grouped by :class:`Section`, empty sections included."""
        out: dict[Section, list[Diagnostic]] = {s: [] for s in Section}
        for diag in self.diagnostics:
            out[diag.section].append(diag)
        return out
