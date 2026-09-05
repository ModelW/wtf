"""The ``compliance check`` logic, independent of any output format."""

from __future__ import annotations

import shutil
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from model_wtf.compliance.declarations.loader import load_declarations, load_folder
from model_wtf.compliance.declarations.schemas import CheckpointStatus
from model_wtf.compliance.discovery import load_units, select_manifest
from model_wtf.compliance.engine import apply_to_folder, evaluate_unit
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.ledger import LedgerStore, effective_status
from model_wtf.compliance.report import (
    DeclarationError,
    Diagnostic,
    Report,
    Scope,
    ScopeKind,
    Severity,
)
from model_wtf.knowledge.loader import load_knowledge

if TYPE_CHECKING:
    from collections.abc import Iterator

    from model_wtf.compliance.declarations.schemas import Finding
    from model_wtf.knowledge.loader import Knowledge

SHARED_FOLDER = "compliance"
SHARED_SCOPE_ID = "shared"


def run_check(
    root: Path,
    *,
    strict: bool,
    framework: str | None = None,
    write: bool = True,
    sha: str = "unknown",
) -> Report:
    """Discover units, validate declarations, run the gates: a :class:`Report`.

    Declaration problems never raise: they are folded into the report with
    :attr:`ExitCode.DECLARATION_ERROR` so that every output format can show
    them the same way. Only genuine bugs propagate (the CLI maps those to
    :attr:`ExitCode.TOOL_ERROR`). Gates only run on units whose
    declarations are error-free: a verdict on a broken registry is noise.

    Parameters
    ----------
    root
        Repository root (already resolved by the caller).
    strict
        Promote "image without compliance" and "nothing declared" from
        warnings to errors.
    framework
        Restrict gates to rules tagged with this framework (``gdpr``,
        ``stride``); ``None``/``"all"`` runs everything.
    write
        Persist applicability, ledger verdicts and findings into each unit
        folder. ``False`` reports without touching the tree.
    sha
        Commit recorded as ``evaluated.sha`` on written checkpoints.
    """
    root = root.resolve()
    try:
        manifest = select_manifest(root)
        units, diagnostics = load_units(manifest, root, strict=strict)
    except DeclarationError as exc:
        return Report(
            root=root,
            manifest=None,
            diagnostics=(exc.diagnostic,),
            exit_code=ExitCode.DECLARATION_ERROR,
        )

    shared_folder = root / SHARED_FOLDER
    scopes = [_inspect(SHARED_SCOPE_ID, ScopeKind.SHARED, shared_folder)]
    scopes.extend(_inspect(unit.id, ScopeKind.UNIT, unit.folder) for unit in units)

    # Declarations: the shared folder is validated once on its own, then
    # every unit is validated and cross-checked against it. A unit whose
    # folder *is* the shared folder (single-image repo) is not re-reported.
    _, shared_diags = load_folder(shared_folder, SHARED_SCOPE_ID)
    diagnostics.extend(shared_diags)
    knowledge = load_knowledge()
    for unit in units:
        ds, unit_diags = load_declarations(unit.folder, shared_folder, unit.id)
        if unit.folder.resolve() == shared_folder.resolve():
            unit_diags = [d for d in unit_diags if d.code == "unknown-reference"]
        diagnostics.extend(unit_diags)
        if any(d.severity is Severity.ERROR for d in unit_diags + shared_diags):
            continue
        evaluation = evaluate_unit(ds, knowledge, framework)
        if write:
            apply_to_folder(unit.folder, evaluation, sha=sha, root=root)
            diagnostics.extend(
                _verdict_diagnostics(unit.id, unit.folder, root, knowledge)
            )
        else:
            with _scratch_copy(unit.folder) as scratch:
                apply_to_folder(scratch, evaluation, sha=sha, root=root)
                diagnostics.extend(
                    _verdict_diagnostics(unit.id, scratch, root, knowledge)
                )

    if all(scope.file_count == 0 for scope in scopes):
        diagnostics.append(
            Diagnostic(
                Severity.ERROR if strict else Severity.WARNING,
                "nothing-declared",
                "Nothing declared: every compliance folder is empty or missing",
                path=root,
            )
        )

    return Report(
        root=root,
        manifest=manifest,
        scopes=tuple(scopes),
        diagnostics=tuple(diagnostics),
        exit_code=_exit_code(diagnostics),
    )


def _exit_code(diagnostics: list[Diagnostic]) -> ExitCode:
    """Worst severity wins: declaration errors (3) over findings (1)."""
    severities = {d.severity for d in diagnostics}
    if Severity.ERROR in severities:
        return ExitCode.DECLARATION_ERROR
    if Severity.FINDING in severities:
        return ExitCode.FINDINGS
    return ExitCode.CLEAN


def _verdict_diagnostics(
    unit_id: str, folder: Path, root: Path, knowledge: Knowledge
) -> list[Diagnostic]:
    """Read the reconciled ledgers + findings and report what blocks.

    ``check`` judges the *files*, not the live evaluation: an ``unknown``
    checkpoint (never evaluated, or re-staged) blocks just like an
    unaccepted ``not_ok``; an ``accepted`` finding past its ``review_by``
    only warns. Findings are annotated at their ``provenance`` (first
    ``path[:line]``), so the GitHub renderer lands them on the right file.
    """
    store = LedgerStore(folder)
    findings = store.all_findings()
    today = datetime.now(tz=UTC).date()
    out: list[Diagnostic] = []
    for file_id, ledger in store.all_ledgers().items():
        for rule_id, entry in sorted(ledger.items()):
            rule = knowledge.rules.get(rule_id)
            title = rule.title if rule else rule_id
            refs = (
                f" [{', '.join(rule.references)}]" if rule and rule.references else ""
            )
            finding = findings.get(entry.finding or "")
            path, line = _provenance(finding, root, store.ledger_path(file_id))
            status = effective_status(entry, findings)
            if status is CheckpointStatus.UNKNOWN:
                why = f" ({entry.staged_because})" if entry.staged_because else ""
                out.append(
                    Diagnostic(
                        Severity.FINDING,
                        rule_id,
                        f"{file_id}: {title}: not evaluated yet{why}",
                        unit_id,
                        store.ledger_path(file_id),
                    )
                )
            elif status is CheckpointStatus.NOT_OK:
                label = f"{entry.finding}: " if entry.finding else ""
                out.append(
                    Diagnostic(
                        Severity.FINDING,
                        rule_id,
                        f"{label}{file_id}: {title}{refs}",
                        unit_id,
                        path,
                        line,
                    )
                )
            elif (
                status is CheckpointStatus.ACCEPTED
                and finding is not None
                and finding.accepted is not None
                and finding.accepted.review_by < today
            ):
                out.append(
                    Diagnostic(
                        Severity.WARNING,
                        "review-overdue",
                        f"{entry.finding}: accepted {rule_id} on {file_id} was due "
                        f"for review on {finding.accepted.review_by.isoformat()}",
                        unit_id,
                        store.finding_path(entry.finding or ""),
                    )
                )
    return out


def _provenance(
    finding: Finding | None, root: Path, fallback: Path
) -> tuple[Path, int | None]:
    """First ``path[:line]`` of a finding as an absolute path + line."""
    if finding is None or not finding.provenance:
        return fallback, None
    first = finding.provenance[0]
    path_str, _, line_str = first.rpartition(":")
    if path_str and line_str.isdigit():
        return root / path_str, int(line_str)
    return root / first, None


@contextmanager
def _scratch_copy(folder: Path) -> Iterator[Path]:
    """A throwaway copy of ``folder`` so ``--no-write`` can still reconcile.

    The verdict is a function of the reconciled files, so the cheapest way
    to report without writing is to reconcile a copy.
    """
    with tempfile.TemporaryDirectory(prefix="model-wtf-") as tmp:
        scratch = Path(tmp) / folder.name
        if folder.is_dir():
            shutil.copytree(folder, scratch)
        else:
            scratch.mkdir()
        yield scratch


def _inspect(scope_id: str, kind: ScopeKind, folder: Path) -> Scope:
    """Build a :class:`Scope` from what is on disk at ``folder``."""
    exists = folder.is_dir()
    return Scope(
        id=scope_id,
        kind=kind,
        path=folder,
        exists=exists,
        file_count=_count_files(folder) if exists else 0,
    )


def _count_files(folder: Path) -> int:
    """Count regular files under ``folder``, ignoring hidden ones.

    Hidden entries (``.gitkeep`` above all) exist to make Git keep an empty
    directory; counting them would turn "empty" into "declared".
    """
    return sum(
        1
        for path in folder.rglob("*")
        if path.is_file()
        and not any(part.startswith(".") for part in path.relative_to(folder).parts)
    )
