"""Locate the repository root, its manifest, and the compliance units.

A *unit* is one deployable image (``api``, ``front``, ...) with its own
``compliance/`` folder. Units are declared in the deployment manifest
(``snow.yml``) so that compliance follows the same shape as deployment;
repos without ``snow.yml`` can use a dedicated ``.model-wtf.yml`` instead.

Manifest shapes are described as Pydantic models: validation errors are
reported verbatim (with their YAML location) as declaration errors.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from model_wtf.compliance.report import DeclarationError, Diagnostic, Severity, Unit

SNOW_MANIFEST = "snow.yml"
FALLBACK_MANIFEST = ".model-wtf.yml"


Discovery = Literal["django", "sveltekit", "none"]
"""Which extractor understands the image's codebase.

``none`` opts an image into compliance without any automatic discovery
(everything declared by hand).
"""

DEFAULT_FOLDER_NAME = "compliance"


class ComplianceBlock(BaseModel):
    """The ``compliance:`` mapping on an image.

    ``discover`` names the discovery engine; ``dir`` relocates the folder
    (relative to the image's build context). When ``dir`` is omitted the
    folder sits next to the Dockerfile, which is where the unit's code is.
    """

    model_config = ConfigDict(extra="forbid")

    discover: Discovery
    dir: str | None = Field(default=None, min_length=1)


class UnitDeclaration(BaseModel):
    """One entry of ``snow.yml#images`` or ``.model-wtf.yml#units``.

    Only the keys relevant to compliance are modelled; everything else a
    Snow image carries (``envs``, ``build_args``, ...) is ignored.
    """

    model_config = ConfigDict(extra="ignore")

    id: str = Field(min_length=1)
    context: str = "."
    dockerfile: str | None = Field(default=None, min_length=1)
    compliance: ComplianceBlock | None = None

    def folder(self, root: Path) -> Path:
        """Absolute compliance folder; requires ``compliance`` to be set."""
        assert self.compliance is not None  # noqa: S101 - caller checks
        return normalise_folder(
            root, self.context, self.dockerfile, self.compliance.dir
        )

    def code_root(self, root: Path) -> Path:
        """Where the unit's code lives: the Dockerfile's folder."""
        base = root / self.context
        if self.dockerfile:
            base = base / Path(self.dockerfile).parent
        return base.resolve()


class _Manifest(BaseModel):
    """Common base: a list of unit declarations with unique ids."""

    model_config = ConfigDict(extra="ignore")

    @property
    def declarations(self) -> list[UnitDeclaration]:
        """The unit list, whatever the concrete manifest calls it."""
        raise NotImplementedError

    @staticmethod
    def _none_as_empty(value: object) -> object:
        """Let ``images:`` with no value mean "no images" rather than a type error."""
        return [] if value is None else value

    @staticmethod
    def _unique_ids(entries: list[UnitDeclaration]) -> list[UnitDeclaration]:
        seen: set[str] = set()
        for entry in entries:
            if entry.id in seen:
                msg = f"duplicate id {entry.id!r}"
                raise ValueError(msg)
            seen.add(entry.id)
        return entries


class SnowManifest(_Manifest):
    """The subset of ``snow.yml`` that compliance cares about."""

    images: list[UnitDeclaration] = []

    _empty = field_validator("images", mode="before")(_Manifest._none_as_empty)
    _check_ids = field_validator("images")(_Manifest._unique_ids)

    @property
    def declarations(self) -> list[UnitDeclaration]:
        """Snow calls units ``images``."""
        return self.images


class ModelWtfManifest(_Manifest):
    """``.model-wtf.yml``: the fallback for repos not deployed via Snow."""

    units: list[UnitDeclaration] = []

    _empty = field_validator("units", mode="before")(_Manifest._none_as_empty)
    _check_ids = field_validator("units")(_Manifest._unique_ids)

    @property
    def declarations(self) -> list[UnitDeclaration]:
        """Units are called ``units`` here."""
        return self.units


def find_repo_root(start: Path) -> Path:
    """Return the nearest ancestor of ``start`` that contains ``.git``.

    Falls back to ``start`` itself when no Git checkout is found, so the
    tool still works on an exported tree. ``.git`` may be a file (worktrees
    and submodules), hence ``exists()`` rather than ``is_dir()``.
    """
    start = start.resolve()
    for candidate in (start, *start.parents):
        if (candidate / ".git").exists():
            return candidate
    return start


def select_manifest(root: Path) -> Path:
    """Pick the manifest to read units from.

    ``snow.yml`` is authoritative when present; ``.model-wtf.yml`` is only
    a fallback for repos not deployed through Snow, never a second source.

    Raises
    ------
    DeclarationError
        When neither file exists.
    """
    for name in (SNOW_MANIFEST, FALLBACK_MANIFEST):
        candidate = root / name
        if candidate.is_file():
            return candidate

    msg = (
        f"No {SNOW_MANIFEST} or {FALLBACK_MANIFEST} found at the repo root; "
        "cannot discover compliance units"
    )
    raise DeclarationError(
        Diagnostic(Severity.ERROR, "manifest-missing", msg, path=root)
    )


def load_units(
    manifest: Path, root: Path, *, strict: bool
) -> tuple[list[Unit], list[Diagnostic]]:
    """Parse ``manifest`` into units plus the diagnostics it produced.

    Entries without a ``compliance`` key are not units; each yields a
    warning (or an error under ``strict``) instead, because an image that
    ships to production with no compliance declaration is exactly what
    this tool exists to catch.

    Raises
    ------
    DeclarationError
        When the file cannot be read or does not validate.
    """
    parsed = _parse_manifest(manifest)
    what = "image" if isinstance(parsed, SnowManifest) else "unit"

    units: list[Unit] = []
    diagnostics: list[Diagnostic] = []

    for entry in parsed.declarations:
        if entry.compliance is None:
            msg = f"{what} {entry.id!r} declares no 'compliance' block"
            diagnostics.append(
                Diagnostic(
                    Severity.ERROR if strict else Severity.WARNING,
                    "unit-no-compliance",
                    msg,
                    entry.id,
                    manifest,
                )
            )
            continue
        units.append(
            Unit(
                entry.id,
                entry.folder(root),
                discover=entry.compliance.discover,
                code_root=entry.code_root(root),
            )
        )

    return units, diagnostics


def normalise_folder(
    root: Path, context: str, dockerfile: str | None, folder: str | None
) -> Path:
    """Resolve the compliance folder of an image.

    ``folder`` (the ``compliance.dir`` key) is relative to ``context``.
    Without it the folder is ``compliance/`` next to the Dockerfile, i.e.
    ``<context>/<dirname(dockerfile)>/compliance``; with no ``dockerfile``
    key Snow assumes ``<context>/Dockerfile`` so it is ``<context>/compliance``.
    ``Path`` arithmetic collapses ``.`` and ``..`` segments, which matters
    for display and equality.
    """
    base = root / context
    if folder is not None:
        return (base / folder).resolve()
    if dockerfile:
        base = base / Path(dockerfile).parent
    return (base / DEFAULT_FOLDER_NAME).resolve()


def _parse_manifest(manifest: Path) -> SnowManifest | ModelWtfManifest:
    """Read and validate ``manifest`` against the model matching its name."""
    model = SnowManifest if manifest.name == SNOW_MANIFEST else ModelWtfManifest
    try:
        data: Any = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        return model.model_validate(data if data is not None else {})
    except (OSError, yaml.YAMLError) as exc:
        msg = f"Cannot read {manifest.name}: {exc}"
        raise _malformed(msg, manifest) from exc
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(loc) for loc in err['loc']) or '<root>'}: {err['msg']}"
            for err in exc.errors()
        )
        msg = f"Invalid {manifest.name}: {details}"
        raise _malformed(msg, manifest) from exc


def _malformed(message: str, manifest: Path) -> DeclarationError:
    """Build the standard error for an unreadable or invalid manifest."""
    return DeclarationError(
        Diagnostic(Severity.ERROR, "malformed-manifest", message, path=manifest)
    )
