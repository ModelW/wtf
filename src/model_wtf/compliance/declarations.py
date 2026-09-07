"""Read and validate the shared declarations (``app.yaml`` + ``parties/``).

Everything here is deterministic and side-effect free: it turns files into
models plus :class:`~model_wtf.compliance.report.Diagnostic` entries. Two
kinds of problems come out, and the exit code depends on which:

* **errors** (``schema-error``, ``unknown-party``, ``app-missing``, ...):
  the declarations are wrong → :attr:`ExitCode.DECLARATION_ERROR`;
* **todos** (``todo``): the declarations are fine but unfinished
  (``!todo`` values) → :attr:`ExitCode.FINDINGS`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import yaml
from pydantic import BaseModel, ValidationError

from model_wtf.compliance.report import Diagnostic, Severity, marker_diagnostics
from model_wtf.compliance.schemas import App, Party, is_valid_id
from model_wtf.compliance.yaml_io import Marker, load_yaml

if TYPE_CHECKING:
    from pathlib import Path

APP_FILE = "app.yaml"
PARTIES_DIR = "parties"
SHARED_SCOPE_ID = "shared"


@dataclass
class Declarations:
    """What was successfully parsed from the shared ``compliance/`` folder."""

    app: App | None = None
    parties: dict[str, Party] = field(default_factory=dict)
    invalid_parties: set[str] = field(default_factory=set)
    """Ids whose file exists but failed validation (already reported)."""
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        """Whether any diagnostic is an error (as opposed to a todo)."""
        return any(d.severity is Severity.ERROR for d in self.diagnostics)

    @property
    def has_todos(self) -> bool:
        """Whether any ``!todo`` value was found."""
        return any(d.code == "todo" for d in self.diagnostics)


def load_declarations(shared: Path) -> Declarations:
    """Parse ``<shared>/app.yaml`` and ``<shared>/parties/*.yaml``.

    A missing shared folder yields a single ``app-missing`` error: the
    repository has not been initialised, and there is nothing else worth
    saying until it is.
    """
    decl = Declarations()
    app_path = shared / APP_FILE
    if not app_path.is_file():
        decl.diagnostics.append(
            Diagnostic(
                Severity.ERROR,
                "app-missing",
                f"{APP_FILE} not found; run `model-wtf compliance init`",
                SHARED_SCOPE_ID,
                app_path,
            )
        )
        return decl

    decl.app = _load_file(app_path, App, decl.diagnostics)
    _load_parties(shared / PARTIES_DIR, decl)
    if decl.app is not None:
        _check_party_refs(decl, app_path)
    return decl


def _load_parties(folder: Path, decl: Declarations) -> None:
    if not folder.is_dir():
        decl.diagnostics.append(
            Diagnostic(
                Severity.ERROR,
                "parties-missing",
                f"{PARTIES_DIR}/ folder not found",
                SHARED_SCOPE_ID,
                folder,
            )
        )
        return
    for path in sorted(folder.glob("*.yaml")):
        party_id = path.stem
        if not is_valid_id(party_id):
            decl.diagnostics.append(
                Diagnostic(
                    Severity.ERROR,
                    "invalid-id",
                    f"party file name {party_id!r} is not a valid id "
                    "(lowercase letters, digits, dashes)",
                    SHARED_SCOPE_ID,
                    path,
                )
            )
            continue
        party = _load_file(path, Party, decl.diagnostics)
        if party is None:
            decl.invalid_parties.add(party_id)
        else:
            decl.parties[party_id] = party


def _check_party_refs(decl: Declarations, app_path: Path) -> None:
    assert decl.app is not None  # noqa: S101 - guarded by caller
    for role in ("controller", "processor"):
        ref = getattr(decl.app, role)
        if ref is None or isinstance(ref, Marker):
            continue
        if ref not in decl.parties and ref not in decl.invalid_parties:
            decl.diagnostics.append(
                Diagnostic(
                    Severity.ERROR,
                    "unknown-party",
                    f"{role} {ref!r} has no file {PARTIES_DIR}/{ref}.yaml",
                    SHARED_SCOPE_ID,
                    app_path,
                )
            )


_BRANCH = re.compile(
    r"^(function-after\[.*\]|function-before\[.*\]|function-wrap\[.*\]|"
    r"tagged-union\[.*\]|union\[.*\]|constrained-str|str|int|bool|list\[.*\]|"
    r"dict\[.*\]|literal\[.*\]|is-instance\[.*\]|nullable|.*\[.*\])$"
)
"""Location segments pydantic adds for the validator or union branch it was
in; they mean nothing to the person editing the YAML."""


def format_errors(exc: ValidationError) -> list[tuple[str, str]]:
    """Flatten a pydantic error into ``(dotted location, message)`` pairs.

    Every human field is a ``T | Marker`` union, so pydantic reports two
    failures per bad value: one for ``T`` and one "should be an instance of
    Marker". The second is noise for the reader and is dropped, as are the
    validator / union branch segments of the location (``function-after[...]``,
    ``constrained-str``). An unexpected key is phrased as such, and the same
    complaint is never repeated.
    """
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for err in exc.errors():
        parts = [str(p) for p in err["loc"]]
        if parts and parts[-1].startswith("is-instance["):
            continue
        kept = [p for p in parts if not _BRANCH.match(p)]
        msg = err["msg"]
        if err["type"] == "extra_forbidden" and kept:
            key = kept.pop()
            msg = f"unexpected key {key!r}"
        pair = (".".join(kept) or "<root>", msg)
        if pair in seen:
            continue
        seen.add(pair)
        out.append(pair)
    return out


def _load_file[M: BaseModel](
    path: Path, model: type[M], diagnostics: list[Diagnostic]
) -> M | None:
    """Validate ``path`` against ``model``; record errors and todos.

    Returns the model on success (even when it has todos) or ``None``
    when the file is unreadable or invalid.
    """
    try:
        data = load_yaml(path)
    except (OSError, yaml.YAMLError) as exc:
        diagnostics.append(
            Diagnostic(
                Severity.ERROR,
                "yaml-error",
                f"cannot read {path.name}: {exc}",
                SHARED_SCOPE_ID,
                path,
            )
        )
        return None
    try:
        instance = model.model_validate(data if data is not None else {})
    except ValidationError as exc:
        for loc, msg in format_errors(exc):
            diagnostics.append(
                Diagnostic(
                    Severity.ERROR,
                    "schema-error",
                    f"{path.name}: {loc}: {msg}",
                    SHARED_SCOPE_ID,
                    path,
                )
            )
        return None
    diagnostics.extend(marker_diagnostics(instance, path, SHARED_SCOPE_ID))
    return instance
