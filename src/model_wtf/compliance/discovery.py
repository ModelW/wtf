"""Locate the repository root, its manifest, and the compliance units.

A *unit* is one deployable image (``api``, ``front``, ...) with its own
``compliance/`` folder. Units are declared in the deployment manifest
(``snow.yml``) so that compliance follows the same shape as deployment;
repos without ``snow.yml`` can use a dedicated ``.model-wtf.yml`` instead.

Manifest shapes are described as Pydantic models: validation errors are
reported verbatim (with their YAML location) as declaration errors.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from model_wtf.compliance.report import DeclarationError, Diagnostic, Severity, Unit

if TYPE_CHECKING:
    from pathlib import Path

SNOW_MANIFEST = "snow.yml"
FALLBACK_MANIFEST = ".model-wtf.yml"


class UnitDeclaration(BaseModel):
    """One entry of ``snow.yml#images`` or ``.model-wtf.yml#units``.

    Only the keys relevant to compliance are modelled; everything else a
    Snow image carries (``dockerfile``, ``envs``, ...) is ignored.
    """

    model_config = ConfigDict(extra="ignore")

    id: str = Field(min_length=1)
    context: str = "."
    compliance: str | None = Field(default=None, min_length=1)


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
            msg = f"{what} {entry.id!r} declares no 'compliance' folder"
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
            Unit(entry.id, normalise_folder(root, entry.context, entry.compliance))
        )

    return units, diagnostics


def normalise_folder(root: Path, context: str, compliance: str) -> Path:
    """Resolve ``<context>/<compliance>`` against ``root``.

    ``Path`` arithmetic already drops ``.`` segments, so ``context: "."``
    yields ``root/compliance`` rather than ``root/./compliance``. ``..``
    segments are collapsed too, which matters for display and equality.
    """
    return (root / context / compliance).resolve()


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
