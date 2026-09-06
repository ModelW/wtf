"""Surface JSON v1: what a code extractor tells model-wtf about one unit.

This schema is the contract between model-wtf and the stack extractors
(``manage.py export_compliance_surface`` in preset-django, the SvelteKit
file extractor, ...). model-wtf owns it: extractors conform to this file,
not the other way round. Extras are allowed at every level so an
extractor can ship facts ahead of a model-wtf release; unknown facts are
simply carried into the ``.gen.yaml`` files untouched.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_ID = "modelw.surface/1"


class Lenient(BaseModel):
    """Base for surface parts: forward-compatible, extras kept."""

    model_config = ConfigDict(extra="allow")


class Auth(Lenient):
    """What the extractor could tell about an entrypoint's authentication."""

    scheme: str | None = Field(
        default=None,
        description="none | session | token | admin | unknown, or the class name.",
    )
    permissions: list[str] = Field(default_factory=list)


class Entrypoint(Lenient):
    """An HTTP/WS route as mounted."""

    id: str = Field(description="http:<METHOD>:<path> or ws:<path>")
    path: str
    methods: list[str] = Field(default_factory=list)
    view: str | None = Field(default=None, description="Dotted callable.")
    namespace: str | None = None
    name: str | None = None
    auth: Auth = Field(default_factory=Auth)
    tags: list[str] = Field(
        default_factory=list,
        description="admin, cms-admin, cms-preview, health, debug-only, docs...",
    )
    params: dict[str, object] = Field(default_factory=dict)
    models_read: list[str] = Field(
        default_factory=list, description="store:<app>.<Model>"
    )
    models_written: list[str] = Field(default_factory=list)
    access_confidence: Literal["high", "medium", "low"] | None = None
    provenance: str | None = Field(default=None, description="file:line of the view")


class PiiHint(Lenient):
    """Heuristic classification of a field."""

    item: str
    confidence: Literal["high", "medium", "low"] = "medium"


class CandidateContent(Lenient):
    """Something seen stored inside an opaque field."""

    name: str
    provenance: str | None = None


class StorageField(Lenient):
    """One model field."""

    name: str
    type: str
    null: bool = False
    unique: bool = False
    primary_key: bool = False
    fk_target: str | None = None
    on_delete: str | None = None
    pii_hints: list[PiiHint] = Field(default_factory=list)
    opaque: bool = False
    candidate_contents: list[CandidateContent] = Field(default_factory=list)


class Lifecycle(Lenient):
    """Retention-relevant facts about a model."""

    soft_delete: bool = False
    history: bool = False
    blob: bool = False
    pk_as_pii: bool = False
    on_delete_chain: str | None = None


class Storage(Lenient):
    """A persisted model."""

    id: str = Field(description="store:<app_label>.<Model>")
    app_label: str
    model: str
    database: str | None = None
    shadow_store: bool = False
    lifecycle: Lifecycle = Field(default_factory=Lifecycle)
    fields: list[StorageField] = Field(default_factory=list)
    provenance: str | None = None


class ConfigKey(Lenient):
    """One environment/config key the unit reads."""

    key: str
    required: bool = False
    is_yaml: bool = False
    sink: str | None = Field(default=None, description="Known third party it feeds.")


class Egress(Lenient):
    """A third party the unit talks to."""

    id: str = Field(description="egress:sdk:<pkg> or egress:host:<host>")
    credential_keys: list[str] = Field(default_factory=list)
    facts: dict[str, object] = Field(default_factory=dict)
    provenance: list[str] = Field(default_factory=list)


class Task(Lenient):
    """A background task or management command."""

    id: str = Field(description="task:<dotted.name>")
    schedule: str | None = None
    kind: str | None = Field(
        default=None, description="procrastinate | celery | command"
    )
    models_read: list[str] = Field(default_factory=list)
    models_written: list[str] = Field(default_factory=list)
    provenance: str | None = None


class Surface(Lenient):
    """The whole extractor output for one unit."""

    schema_: str = Field(alias="schema", description=f"Must be {SCHEMA_ID}.")
    unit: str
    stack: list[str] = Field(default_factory=lambda: ["django"])
    entrypoints: list[Entrypoint] = Field(default_factory=list)
    storage: list[Storage] = Field(default_factory=list)
    config: list[ConfigKey] = Field(default_factory=list)
    egress: list[Egress] = Field(default_factory=list)
    tasks: list[Task] = Field(default_factory=list)
    controls: dict[str, object] = Field(default_factory=dict)

    model_config = ConfigDict(extra="allow", populate_by_name=True)


class SurfaceError(Exception):
    """The extractor could not run or produced something that is not a Surface."""


def parse_surface(data: object) -> Surface:
    """Validate raw JSON into a :class:`Surface`, checking the schema id."""
    from pydantic import ValidationError

    try:
        surface = Surface.model_validate(data)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
        )
        msg = f"surface JSON does not match {SCHEMA_ID}: {details}"
        raise SurfaceError(msg) from exc
    if surface.schema_ != SCHEMA_ID:
        msg = f"unsupported surface schema {surface.schema_!r} (expected {SCHEMA_ID})"
        raise SurfaceError(msg)
    return surface
