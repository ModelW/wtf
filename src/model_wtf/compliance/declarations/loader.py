"""Read a ``compliance/`` folder into validated, cross-checked declarations.

Two layers:

* :func:`load_folder` reads *one* folder: it maps files to kinds by their
  location, validates each against its schema and pairs every state file
  with its ``.gen.yaml`` twin when present. Problems become
  :class:`~model_wtf.compliance.report.Diagnostic` objects with a line.
* :func:`load_declarations` stacks a unit folder on the repo-root shared
  folder (unit wins) and verifies that every reference between files
  resolves. Unknown references are errors: a registry pointing at a
  recipient nobody described is not a registry.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import BaseModel, ValidationError

from model_wtf.compliance.declarations.ids import (
    element_path_id,
    id_from_path,
    split_checkpoint,
)
from model_wtf.compliance.declarations.schemas import (
    Activity,
    Actor,
    Assumption,
    Controller,
    DataObject,
    Finding,
    Generated,
    Ledger,
    Recipient,
    Security,
)
from model_wtf.compliance.declarations.yaml_lines import LineDict, line_of, load_yaml
from model_wtf.compliance.report import Diagnostic, Severity

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator
    from pathlib import Path


class Kind(StrEnum):
    """Every kind of declaration file, named after its folder (or file)."""

    CONTROLLER = "controller"
    SECURITY = "security"
    ACTOR = "actors"
    ASSUMPTION = "assumptions"
    RECIPIENT = "recipients"
    ACTIVITY = "processing"
    DATA_OBJECT = "data"
    LEDGER = "elements"
    FINDING = "findings"


SINGLETONS: dict[Kind, type[BaseModel]] = {
    Kind.CONTROLLER: Controller,
    Kind.SECURITY: Security,
}
"""Kinds declared by a single top-level file (``controller.yaml``)."""

COLLECTIONS: dict[Kind, type[BaseModel]] = {
    Kind.ACTOR: Actor,
    Kind.ASSUMPTION: Assumption,
    Kind.RECIPIENT: Recipient,
    Kind.ACTIVITY: Activity,
    Kind.DATA_OBJECT: DataObject,
    Kind.LEDGER: Ledger,
    Kind.FINDING: Finding,
}
"""Kinds declared as one file per id inside a sub-folder."""

SHARED_KINDS = frozenset({Kind.CONTROLLER, Kind.ACTOR, Kind.ASSUMPTION, Kind.RECIPIENT})
"""Kinds a unit may inherit from the repo-root ``compliance/`` folder."""

GEN_SUFFIX = ".gen.yaml"
STATE_SUFFIX = ".yaml"


@dataclass(frozen=True, slots=True)
class Declared[M: BaseModel]:
    """One validated declaration together with where it came from.

    Parameters
    ----------
    id
        The id derived from the file name.
    path
        The state file (or, for gen-only pairs, the ``.gen.yaml``).
    model
        The validated state model, ``None`` when only a ``.gen`` exists.
    gen
        The validated ``.gen.yaml`` twin, when present.
    """

    id: str
    path: Path
    model: M | None
    gen: Generated | None = None


@dataclass(slots=True)
class Folder:
    """Everything declared inside one ``compliance/`` folder."""

    path: Path
    controller: Declared[Controller] | None = None
    security: Declared[Security] | None = None
    collections: dict[Kind, dict[str, Declared[Any]]] = field(
        default_factory=lambda: {kind: {} for kind in COLLECTIONS}
    )

    def get(self, kind: Kind) -> dict[str, Declared[Any]]:
        """The declarations of ``kind``, keyed by id."""
        return self.collections[kind]


@dataclass(slots=True)
class DeclarationSet:
    """A unit folder resolved against the shared folder.

    Lookups on shared kinds fall back to the shared folder; everything
    else is unit-local. When the unit folder *is* the shared folder (a
    single-image repo) both attributes point at the same object.
    """

    unit: Folder
    shared: Folder

    def resolve(self, kind: Kind, item_id: str) -> Declared[Any] | None:
        """Find ``item_id`` of ``kind`` in the unit, then (if shared) the root."""
        found = self.unit.get(kind).get(item_id)
        if found is None and kind in SHARED_KINDS:
            found = self.shared.get(kind).get(item_id)
        return found

    def all(self, kind: Kind) -> dict[str, Declared[Any]]:
        """Union of unit and (for shared kinds) root declarations, unit first."""
        merged: dict[str, Declared[Any]] = {}
        if kind in SHARED_KINDS:
            merged.update(self.shared.get(kind))
        merged.update(self.unit.get(kind))
        return merged

    @property
    def controller(self) -> Declared[Controller] | None:
        """The controller, unit-local first, else shared."""
        return self.unit.controller or self.shared.controller


# ---------------------------------------------------------------------------
# Folder loading
# ---------------------------------------------------------------------------


def load_folder(folder: Path, scope_id: str) -> tuple[Folder, list[Diagnostic]]:
    """Validate every declaration file directly under ``folder``.

    Files this version does not know (a ``README.md``, the attestation
    lock, a stray note) are ignored; only ``.yaml`` files in the wrong
    place produce a warning, because that is almost always a misfiled
    declaration.
    """
    result = Folder(path=folder)
    diagnostics: list[Diagnostic] = []
    if not folder.is_dir():
        return result, diagnostics

    for kind, model in SINGLETONS.items():
        path = folder / f"{kind.value}{STATE_SUFFIX}"
        if path.is_file():
            declared = _load_pair(path, model, kind, scope_id, diagnostics)
            setattr(result, kind.value, declared)

    for kind, model in COLLECTIONS.items():
        for path in _state_files(folder / kind.value):
            declared = _load_pair(path, model, kind, scope_id, diagnostics)
            if declared is not None:
                result.get(kind)[declared.id] = declared

    for path in sorted(folder.glob(f"*{STATE_SUFFIX}")):
        if id_from_path(path.name) not in {k.value for k in SINGLETONS}:
            diagnostics.append(
                Diagnostic(
                    Severity.WARNING,
                    "unknown-file",
                    f"{path.name} is not a known declaration file; ignored",
                    scope_id,
                    path,
                )
            )
    return result, diagnostics


def _state_files(sub: Path) -> Iterator[Path]:
    """Yield one path per declared id: the state file, else the lone ``.gen``."""
    if not sub.is_dir():
        return
    seen: set[str] = set()
    for path in sorted(sub.glob(f"*{STATE_SUFFIX}")):
        item_id = id_from_path(path.name)
        if item_id in seen:
            continue
        seen.add(item_id)
        state = sub / f"{item_id}{STATE_SUFFIX}"
        yield state if state.is_file() else path


def _load_pair[M: BaseModel](
    path: Path,
    model: type[M],
    kind: Kind,
    scope_id: str,
    diagnostics: list[Diagnostic],
) -> Declared[M] | None:
    """Load a state file and its ``.gen.yaml`` twin (either may be absent)."""
    item_id = id_from_path(path.name)
    is_gen_only = path.name.endswith(GEN_SUFFIX)
    gen_path = path.parent / f"{item_id}{GEN_SUFFIX}"

    state: M | None = None
    if not is_gen_only:
        state = _validate_file(path, model, scope_id, diagnostics)
        if state is None:
            return None

    gen: Generated | None = None
    if gen_path.is_file():
        gen = _validate_file(gen_path, Generated, scope_id, diagnostics)
        if gen is None:
            return None

    if kind in SINGLETONS and is_gen_only:
        return None
    return Declared(id=item_id, path=path, model=state, gen=gen)


def _validate_file[M: BaseModel](
    path: Path, model: type[M], scope_id: str, diagnostics: list[Diagnostic]
) -> M | None:
    """Parse and validate one YAML file, appending diagnostics on failure."""
    try:
        data = load_yaml(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        line = getattr(getattr(exc, "problem_mark", None), "line", None)
        diagnostics.append(
            Diagnostic(
                Severity.ERROR,
                "unparsable-yaml",
                f"Cannot read {path.name}: {exc}",
                scope_id,
                path,
                line + 1 if line is not None else None,
            )
        )
        return None

    if not isinstance(data, LineDict):
        diagnostics.append(
            Diagnostic(
                Severity.ERROR,
                "invalid-declaration",
                f"{path.name} must contain a YAML mapping",
                scope_id,
                path,
                1,
            )
        )
        return None

    if "id" in data:
        diagnostics.append(
            Diagnostic(
                Severity.ERROR,
                "id-in-file",
                f"{path.name} carries an 'id' key; the id is the file name",
                scope_id,
                path,
                data.key_lines.get("id"),
            )
        )
        return None

    try:
        return model.model_validate(data)
    except ValidationError as exc:
        for err in exc.errors():
            loc = ".".join(str(part) for part in err["loc"]) or "<root>"
            diagnostics.append(
                Diagnostic(
                    Severity.ERROR,
                    "invalid-declaration",
                    f"{path.name}: {loc}: {err['msg']}",
                    scope_id,
                    path,
                    line_of(data, err["loc"]),
                )
            )
        return None


# ---------------------------------------------------------------------------
# Cross-reference integrity
# ---------------------------------------------------------------------------


def load_declarations(
    unit_folder: Path, shared_folder: Path, scope_id: str
) -> tuple[DeclarationSet, list[Diagnostic]]:
    """Load a unit against the shared folder and check every reference.

    The shared folder is loaded again for each unit (it is small), which
    keeps this function free of hidden state; the caller can load it once
    via :func:`load_folder` if it wants to report *its* diagnostics only
    once, which is what ``check`` does.
    """
    unit, diagnostics = load_folder(unit_folder, scope_id)
    if unit_folder.resolve() == shared_folder.resolve():
        shared = unit
    else:
        shared, _ = load_folder(shared_folder, scope_id)

    declarations = DeclarationSet(unit=unit, shared=shared)
    diagnostics.extend(check_integrity(declarations, scope_id))
    return declarations, diagnostics


def check_integrity(declarations: DeclarationSet, scope_id: str) -> list[Diagnostic]:
    """Verify that every cross-file reference resolves."""
    out: list[Diagnostic] = []
    out.extend(_check_activities(declarations, scope_id))
    out.extend(_check_data_objects(declarations, scope_id))
    out.extend(_check_ledgers(declarations, scope_id))
    for finding in declarations.unit.get(Kind.FINDING).values():
        if finding.model is not None:
            out.extend(_check_finding(declarations, finding, finding.model, scope_id))
    return out


def _check_activities(ds: DeclarationSet, scope_id: str) -> Iterator[Diagnostic]:
    """Activities point at recipients, actors and (via .gen) data objects."""
    for activity in ds.unit.get(Kind.ACTIVITY).values():
        model: Activity | None = activity.model
        if model is None:
            continue
        yield from _unresolved(
            ds, Kind.RECIPIENT, model.recipients, activity, "recipients", scope_id
        )
        yield from _unresolved(
            ds,
            Kind.ACTOR,
            model.data_subject_categories,
            activity,
            "data_subject_categories",
            scope_id,
        )
        if activity.gen is not None:
            targets = (activity.gen.model_extra or {}).get("data_objects") or {}
            yield from _unresolved(
                ds,
                Kind.DATA_OBJECT,
                list(targets),
                activity,
                "data_objects",
                scope_id,
                path=activity.path.parent / f"{activity.id}{GEN_SUFFIX}",
            )


def _check_data_objects(ds: DeclarationSet, scope_id: str) -> Iterator[Diagnostic]:
    """Data objects point at actors."""
    for data_object in ds.unit.get(Kind.DATA_OBJECT).values():
        model: DataObject | None = data_object.model
        if model is None:
            continue
        yield from _unresolved(
            ds,
            Kind.ACTOR,
            model.subject_categories,
            data_object,
            "subject_categories",
            scope_id,
        )


def _check_ledgers(ds: DeclarationSet, scope_id: str) -> Iterator[Diagnostic]:
    """Ledger entries with a ``finding`` point at an existing finding file."""
    for ledger in ds.unit.get(Kind.LEDGER).values():
        model: Ledger | None = ledger.model
        if model is None:
            continue
        for rule_id, checkpoint in model.checkpoints.items():
            target = checkpoint.finding
            if target and ds.resolve(Kind.FINDING, target) is None:
                yield _dangling(ledger, f"{rule_id}.finding", target, scope_id)


def _check_finding(
    ds: DeclarationSet, finding: Declared[Finding], model: Finding, scope_id: str
) -> Iterable[Diagnostic]:
    """A finding must point at an existing checkpoint and assumption."""
    try:
        rule_id, element = split_checkpoint(model.checkpoint)
    except ValueError as exc:
        yield Diagnostic(
            Severity.ERROR,
            "invalid-declaration",
            f"{finding.path.name}: checkpoint: {exc}",
            scope_id,
            finding.path,
            _line(finding.path, ("checkpoint",)),
        )
        return

    ledger = ds.resolve(Kind.LEDGER, element) or ds.resolve(
        Kind.LEDGER, element_path_id(element)
    )
    if ledger is None or (
        ledger.model is not None and rule_id not in ledger.model.checkpoints
    ):
        yield _dangling(finding, "checkpoint", model.checkpoint, scope_id)

    assumption = model.accepted.assumption if model.accepted else None
    if assumption and ds.resolve(Kind.ASSUMPTION, assumption) is None:
        yield _dangling(finding, "accepted.assumption", assumption, scope_id)


def _unresolved(
    ds: DeclarationSet,
    kind: Kind,
    targets: Iterable[str],
    source: Declared[Any],
    key: str,
    scope_id: str,
    path: Path | None = None,
) -> Iterator[Diagnostic]:
    """Yield one diagnostic per target id that does not resolve."""
    for index, target in enumerate(targets):
        if ds.resolve(kind, target) is None:
            yield _dangling(source, key, target, scope_id, path, index)


def _dangling(
    source: Declared[Any],
    key: str,
    target: str,
    scope_id: str,
    path: Path | None = None,
    index: int | None = None,
) -> Diagnostic:
    """Build the standard "unknown reference" error.

    ``index`` locates the offending entry inside a list-valued key so the
    line points at the bad item, not at the list header. Mapping-valued
    keys (``data_objects: {id: [...]}``) are located by the target itself.
    """
    file = path or source.path
    loc: tuple[str | int, ...] = tuple(key.split("."))
    if index is not None:
        loc = (*loc, index)
    return Diagnostic(
        Severity.ERROR,
        "unknown-reference",
        f"{file.name}: {key}: unknown reference {target!r}",
        scope_id,
        file,
        _line(file, loc if index is not None else (*loc, target)),
    )


def _line(path: Path, loc: tuple[str | int, ...]) -> int | None:
    """Best-effort line lookup by re-reading the file (integrity pass only).

    Integrity runs on validated models, which no longer carry line marks;
    re-parsing a handful of small files is cheaper than threading the raw
    data through every model.
    """
    try:
        data = load_yaml(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    return line_of(data, loc)
