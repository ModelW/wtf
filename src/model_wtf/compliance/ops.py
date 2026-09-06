"""Operations: what a touchpoint *does* to a data item.

``read | write`` says nothing about rights. A touchpoint declares its
handling of each item with a closed verb set, and each verb carries only the
metadata that verb needs. Ops state facts about the code — nothing about
policy lives here; the rights derivation (KFF-208) reads them.

Manifest forms, all equivalent to a list of ops per ref::

    data:
      - api:people.User.email                                  # bare = read
      - api:orders.Order.user: create                          # one verb
      - api:orders.Order.total: [create, read]                 # several
      - api:people.User.email: {rectify: {by: subject}}        # with metadata
      - api:people.User.*: {erase: {by: subject, mode: anonymise}}   # glob
      - api:cart.Cart.*: {retention_purge: {after: {days: 30},
                                            from: api:cart.Cart.last_used_at}}
      - api:people.User.opt_in: {create: {consent_for: newsletter}}

``write`` is accepted as a deprecated alias for ``[create, update]``
(``op-ambiguous`` warning) so older manifests keep working until re-reviewed.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

__all__ = [
    "OPS_HELP",
    "WRITE_ALIAS",
    "Access",
    "AnyOp",
    "ConsentWithdraw",
    "Create",
    "Delete",
    "Duration",
    "Erase",
    "Object",
    "Op",
    "OpError",
    "OpSpec",
    "Portability",
    "Read",
    "Rectify",
    "Restrict",
    "RetentionPurge",
    "Update",
    "describe",
    "parse_ops",
    "parse_ops_json",
    "render_ops",
]


class Op(StrEnum):
    """The closed verb set."""

    CREATE = "create"
    """The item enters the system here (collection point)."""

    READ = "read"
    """Displayed, listed, used."""

    UPDATE = "update"
    """Staff or system change with no rights meaning (an order status)."""

    RECTIFY = "rectify"
    """The subject corrects their data, or staff does on request (Art. 16)."""

    ACCESS = "access"
    """The subject sees what is held about them (Art. 15)."""

    PORTABILITY = "portability"
    """Machine-readable copy of subject-provided data (Art. 20)."""

    ERASE = "erase"
    """Erasure on request or on an event (Art. 17)."""

    RETENTION_PURGE = "retention_purge"
    """Automatic expiry after a duration (Art. 5(1)(e)); the code is the policy."""

    DELETE = "delete"
    """Plain deletion with no compliance meaning (a cart line removed)."""

    CONSENT_WITHDRAW = "consent_withdraw"
    """Consent for an activity can be withdrawn here (Art. 7(3))."""

    OBJECT = "object"
    """Opt-out recorded (Art. 21)."""

    RESTRICT = "restrict"
    """Processing restriction flagged (Art. 18)."""


WRITE_ALIAS = "write"
"""Deprecated verb, expanded to ``create`` + ``update``."""

By = Literal["subject", "staff"]


class OpSpec(BaseModel):
    """Base of every op: unknown keys are errors, ``op`` is fixed per subclass."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)
    op: Op

    def payload(self) -> dict[str, Any]:
        """The metadata alone, by alias (``from``, ``for``), defaults dropped."""
        return self.model_dump(
            exclude={"op"}, exclude_none=True, exclude_defaults=True, by_alias=True
        )

    def to_yaml(self) -> Any:
        """Manifest form: the bare verb when there is no metadata."""
        payload = self.payload()
        return self.op.value if not payload else {self.op.value: payload}

    def label(self) -> str:
        """Short human form: ``erase(by=subject, mode=anonymise)``."""
        payload = self.payload()
        if not payload:
            return self.op.value
        bits = ", ".join(f"{k}={_flat(v)}" for k, v in payload.items())
        return f"{self.op.value}({bits})"


def _flat(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(f"{k} {v}" for k, v in value.items())
    return str(value)


class Create(OpSpec):
    """Collection point; with ``consent_for`` the stored value is the proof."""

    op: Literal[Op.CREATE] = Op.CREATE
    consent_for: str | None = Field(
        default=None, description="Activity slug this value records consent for"
    )


class Read(OpSpec):
    """Displayed, listed, used."""

    op: Literal[Op.READ] = Op.READ


class Update(OpSpec):
    """Change with no rights meaning."""

    op: Literal[Op.UPDATE] = Op.UPDATE


class Rectify(OpSpec):
    """Art. 16: the subject, or staff on request, corrects the value."""

    op: Literal[Op.RECTIFY] = Op.RECTIFY
    by: By


class Access(OpSpec):
    """Art. 15: the subject sees what is held about them."""

    op: Literal[Op.ACCESS] = Op.ACCESS
    by: Literal["subject"] = "subject"
    format: str | None = None


class Portability(OpSpec):
    """Art. 20: machine-readable copy handed to the subject."""

    op: Literal[Op.PORTABILITY] = Op.PORTABILITY
    format: str = Field(description="Machine-readable format: json, csv, ...")


class Erase(OpSpec):
    """Art. 17: erasure on request (``by``) and/or on an event (``on``)."""

    op: Literal[Op.ERASE] = Op.ERASE
    by: By | None = Field(default=None, description="Who triggers it (on request)")
    mode: Literal["delete", "anonymise"] = "delete"
    on: str | None = Field(
        default=None, description="Event that triggers it: account_closed, ..."
    )

    @model_validator(mode="after")
    def _trigger(self) -> Erase:
        if self.by is None and self.on is None:
            msg = "erase needs `by` (on request) or `on` (an event), or both"
            raise ValueError(msg)
        return self


class Duration(BaseModel):
    """``{days: 30}`` / ``{months: 6}`` / ``{years: 10}`` — exactly one."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    days: int | None = Field(default=None, gt=0)
    months: int | None = Field(default=None, gt=0)
    years: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def _one_unit(self) -> Duration:
        given = [u for u in ("days", "months", "years") if getattr(self, u)]
        if len(given) != 1:
            msg = "after: give exactly one of days, months, years"
            raise ValueError(msg)
        return self

    def __str__(self) -> str:
        unit = next(u for u in ("days", "months", "years") if getattr(self, u))
        return f"{getattr(self, unit)} {unit}"


class RetentionPurge(OpSpec):
    """Art. 5(1)(e): automatic expiry; the code is the retention policy."""

    op: Literal[Op.RETENTION_PURGE] = Op.RETENTION_PURGE
    after: Duration
    from_: str = Field(
        alias="from",
        description="Full data ref of the timestamp the duration counts from",
    )


class Delete(OpSpec):
    """Plain deletion with no compliance meaning."""

    op: Literal[Op.DELETE] = Op.DELETE


class ConsentWithdraw(OpSpec):
    """Art. 7(3): consent for an activity can be withdrawn here."""

    op: Literal[Op.CONSENT_WITHDRAW] = Op.CONSENT_WITHDRAW
    for_: str = Field(alias="for", description="Activity slug")


class Object(OpSpec):
    """Art. 21: the subject's objection is recorded."""

    op: Literal[Op.OBJECT] = Op.OBJECT
    by: Literal["subject"] = "subject"


class Restrict(OpSpec):
    """Art. 18: processing restriction flagged."""

    op: Literal[Op.RESTRICT] = Op.RESTRICT
    by: By


AnyOp = Annotated[
    Create
    | Read
    | Update
    | Rectify
    | Access
    | Portability
    | Erase
    | RetentionPurge
    | Delete
    | ConsentWithdraw
    | Object
    | Restrict,
    Field(discriminator="op"),
]

_CLASSES: dict[str, type[OpSpec]] = {
    Op.CREATE: Create,
    Op.READ: Read,
    Op.UPDATE: Update,
    Op.RECTIFY: Rectify,
    Op.ACCESS: Access,
    Op.PORTABILITY: Portability,
    Op.ERASE: Erase,
    Op.RETENTION_PURGE: RetentionPurge,
    Op.DELETE: Delete,
    Op.CONSENT_WITHDRAW: ConsentWithdraw,
    Op.OBJECT: Object,
    Op.RESTRICT: Restrict,
}

OPS_HELP = (
    "create[{consent_for}] | read | update | rectify{by: subject|staff} | "
    "access | portability{format} | erase{by?, mode: delete|anonymise, on?} | "
    "retention_purge{after: {days|months|years}, from: <full ref>} | delete | "
    "consent_withdraw{for} | object | restrict{by}"
)
"""One-line vocabulary reminder for error messages and tool descriptions."""


class OpError(ValueError):
    """An op the vocabulary does not accept; the message names what is wrong."""


def parse_ops(value: Any) -> tuple[list[OpSpec], list[str]]:
    """Parse one ``data`` entry's value into ops.

    ``value`` is what follows the ref in a manifest: ``None`` (bare ref),
    a verb, a list of verbs / one-key mappings, or a one-key mapping
    ``{verb: metadata}``. Returns the ops and the warnings raised on the
    way (today only the ``write`` alias).

    Raises
    ------
    OpError
        Unknown verb, metadata on a verb that takes none, missing or
        misspelt metadata.
    """
    warnings: list[str] = []
    if value is None:
        return [Read()], warnings
    items = value if isinstance(value, list) else [value]
    if not items:
        msg = "an empty op list says nothing; drop the value for a bare read"
        raise OpError(msg)
    out: list[OpSpec] = []
    for item in items:
        if isinstance(item, str):
            out.extend(_expand(item, {}, warnings))
        elif isinstance(item, dict) and len(item) == 1:
            ((verb, meta),) = item.items()
            if meta is not None and not isinstance(meta, dict):
                msg = f"{verb}: metadata must be a mapping, got {meta!r}"
                raise OpError(msg)
            out.extend(_expand(str(verb), meta or {}, warnings))
        else:
            msg = f"op must be a verb or {{verb: metadata}}, got {item!r} ({OPS_HELP})"
            raise OpError(msg)
    return _dedupe(out), warnings


def _expand(verb: str, meta: dict[str, Any], warnings: list[str]) -> list[OpSpec]:
    if verb == WRITE_ALIAS:
        if meta:
            msg = "write takes no metadata; it is a deprecated alias for create+update"
            raise OpError(msg)
        warnings.append(
            "`write` is ambiguous (create? update?); it is read as [create, update] "
            "— restate what the code does"
        )
        return [Create(), Update()]
    cls = _CLASSES.get(verb)
    if cls is None:
        msg = f"unknown op {verb!r}; use one of: {OPS_HELP}"
        raise OpError(msg)
    try:
        return [cls.model_validate(meta)]
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(p) for p in e['loc']) or verb}: {e['msg']}"
            for e in exc.errors()
        )
        msg = f"{verb}: {details}"
        raise OpError(msg) from exc


def _dedupe(ops: list[OpSpec]) -> list[OpSpec]:
    seen: list[OpSpec] = []
    for op in ops:
        if op not in seen:
            seen.append(op)
    return seen


def parse_ops_json(items: list[dict[str, Any]]) -> tuple[list[OpSpec], list[str]]:
    """Parse the tool form ``[{"op": "erase", "by": "subject"}, ...]``."""
    warnings: list[str] = []
    out: list[OpSpec] = []
    for item in items:
        if not isinstance(item, dict) or "op" not in item:
            msg = f"each op is {{op, ...metadata}}, got {item!r}"
            raise OpError(msg)
        meta = {k: v for k, v in item.items() if k != "op"}
        out.extend(_expand(str(item["op"]), meta, warnings))
    return _dedupe(out), warnings


def render_ops(ops: list[OpSpec]) -> Any:
    """Manifest value for a list of ops: ``None`` for a bare read, else YAML."""
    if not ops or (len(ops) == 1 and isinstance(ops[0], Read)):
        return None
    forms = [op.to_yaml() for op in ops]
    return forms[0] if len(forms) == 1 else forms


def describe(ops: list[OpSpec]) -> str:
    """``create, erase(by=subject)`` for tables and narration."""
    return ", ".join(op.label() for op in ops)
