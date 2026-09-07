r"""Operations: what a touchpoint *does* to a data item.

Touchpoints state **facts about the code**, never a legal qualification:
the closed verb set is what a reviewer can read off a view or a task,
and the rights derivation (:mod:`rights`) turns those facts into Art. 15-21
answers using who the touchpoint serves (:attr:`Touchpoint.scope`).

Manifest forms, all equivalent to a list of ops per ref::

    data:
      - api:people.User.email                                  # bare = read
      - api:orders.Order.user: create                          # one verb
      - api:orders.Order.total: [create, read]                 # several
      - api:people.User.*: {delete: {mode: anonymise}}         # with metadata
      - api:geo.Address.*: {retention_purge: {after: settings.ANONYMOUS_ADDRESS_MAX_AGE,
                                              since: last use, when: anonymous only}}
      - api:people.User.*: {portability: {format: json}}
      - api:people.User.opt_in: {create: {consent_for: newsletter}}

| verb | metadata | fact |
| -- | -- | -- |
| ``create`` | ``consent_for``? | the value enters the system here |
| ``read`` | — | displayed, listed, used, mailed |
| ``update`` | — | the value is changed here |
| ``delete`` | ``mode: delete\|anonymise`` | the row / value goes away here |
| ``retention_purge`` | ``after``, ``since``, ``when`` | removed after a delay |
| ``portability`` | ``format`` | a machine-readable copy is handed out |
| ``consent_withdraw`` | ``for`` | revokes a consent for that activity |

Older verbs (``write``, ``rectify``, ``access``, ``erase``, ``object``,
``restrict``) still parse: they are folded onto the facts above with an
``op-ambiguous`` warning so existing manifests keep loading.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

__all__ = [
    "LEGACY_VERBS",
    "OPS_HELP",
    "WRITE_ALIAS",
    "AnyOp",
    "ConsentWithdraw",
    "Create",
    "Delete",
    "Duration",
    "Op",
    "OpError",
    "OpSpec",
    "Portability",
    "Read",
    "RetentionPurge",
    "Update",
    "describe",
    "parse_ops",
    "parse_ops_json",
    "render_ops",
]


class Op(StrEnum):
    """The closed verb set: facts a reviewer reads off the code."""

    CREATE = "create"
    """The value enters the system here."""

    READ = "read"
    """Displayed, listed, used, mailed."""

    UPDATE = "update"
    """The value is changed here."""

    DELETE = "delete"
    """The row or value goes away here (``mode: anonymise`` keeps the row)."""

    RETENTION_PURGE = "retention_purge"
    """A task removes it after a delay (Art. 5(1)(e)); the code is the policy."""

    PORTABILITY = "portability"
    """A machine-readable copy is handed out (Art. 20)."""

    CONSENT_WITHDRAW = "consent_withdraw"
    """Revokes the consent recorded for an activity (Art. 7(3))."""


WRITE_ALIAS = "write"
"""Deprecated verb, expanded to ``create`` + ``update``."""

LEGACY_VERBS: dict[str, tuple[str, str]] = {
    "rectify": ("update", "a subject-facing update IS rectification"),
    "access": ("read", "a subject-facing read IS access"),
    "erase": ("delete", "a subject-facing delete IS erasure"),
    "object": ("update", "an opt-out is an update of the flag"),
    "restrict": ("update", "a restriction is an update of the flag"),
}
"""Verbs that qualified the code legally; folded onto the fact they imply.
The right is derived from who the touchpoint serves, not from the verb."""


class OpSpec(BaseModel):
    """Base of every op: unknown keys are errors, ``op`` is fixed per subclass."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)
    op: Op

    def payload(self) -> dict[str, Any]:
        """The metadata alone, by alias (``for``), defaults dropped."""
        return self.model_dump(
            exclude={"op"}, exclude_none=True, exclude_defaults=True, by_alias=True
        )

    def to_yaml(self) -> Any:
        """Manifest form: the bare verb when there is no metadata."""
        payload = self.payload()
        return self.op.value if not payload else {self.op.value: payload}

    def label(self) -> str:
        """Short human form: ``delete(mode=anonymise)``."""
        payload = self.payload()
        if not payload:
            return self.op.value
        bits = ", ".join(f"{k}={_flat(v)}" for k, v in payload.items())
        return f"{self.op.value}({bits})"


def _flat(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(f"{v} {k}" for k, v in value.items())
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
    """The value is changed here."""

    op: Literal[Op.UPDATE] = Op.UPDATE


class Delete(OpSpec):
    """The row or value goes away; ``anonymise`` keeps the row, blanks the value."""

    op: Literal[Op.DELETE] = Op.DELETE
    mode: Literal["delete", "anonymise"] = "delete"


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
    """Art. 5(1)(e): automatic removal after a delay; the code is the policy.

    ``after`` is the delay as the code states it: a duration
    (``{days: 30}``) or the name of the setting holding it
    (``settings.ANONYMOUS_ADDRESS_MAX_AGE``). ``since`` names the clock in
    plain words ("last use", "creation"); ``when`` the case, if the purge
    only covers some rows ("anonymous addresses only"). Several purge ops on
    one item are several cases.
    """

    op: Literal[Op.RETENTION_PURGE] = Op.RETENTION_PURGE
    after: Duration | str = Field(
        description="A duration ({days: 30}) or the setting name that holds it"
    )
    since: str = Field(description="What starts the clock: last use, creation, ...")
    when: str | None = Field(
        default=None, description="Which rows, when not all: anonymous only, ..."
    )

    @field_validator("after")
    @classmethod
    def _setting_name(cls, value: Duration | str) -> Duration | str:
        if isinstance(value, str) and not re.fullmatch(r"[A-Za-z_][\w.]*", value):
            msg = "after: a duration ({days: N}) or a setting name (settings.X)"
            raise ValueError(msg)
        return value

    def sentence(self) -> str:
        """``7 days after last use, anonymous only``."""
        text = f"{self.after} after {self.since}"
        return f"{text}, {self.when}" if self.when else text


class Portability(OpSpec):
    """Art. 20: machine-readable copy handed to the subject."""

    op: Literal[Op.PORTABILITY] = Op.PORTABILITY
    format: str = Field(description="Machine-readable format: json, csv, ...")


class ConsentWithdraw(OpSpec):
    """Art. 7(3): consent for an activity can be withdrawn here."""

    op: Literal[Op.CONSENT_WITHDRAW] = Op.CONSENT_WITHDRAW
    for_: str = Field(alias="for", description="Activity slug")


AnyOp = Annotated[
    Create | Read | Update | Delete | RetentionPurge | Portability | ConsentWithdraw,
    Field(discriminator="op"),
]

_CLASSES: dict[str, type[OpSpec]] = {
    Op.CREATE: Create,
    Op.READ: Read,
    Op.UPDATE: Update,
    Op.DELETE: Delete,
    Op.RETENTION_PURGE: RetentionPurge,
    Op.PORTABILITY: Portability,
    Op.CONSENT_WITHDRAW: ConsentWithdraw,
}

OPS_HELP = (
    "create[{consent_for}] | read | update | delete[{mode: delete|anonymise}] | "
    "retention_purge{after: {days|months|years} or settings.NAME, since, when?} | "
    "portability{format} | consent_withdraw{for}"
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


_YAML_BOOL_KEYS = {True: "on", False: "off"}
"""PyYAML reads the bare key ``on`` as ``True`` (YAML 1.1 booleans); ``erase:
{on: account_closed}`` is too natural to forbid, so the key is put back."""


def _expand(verb: str, meta: dict[Any, Any], warnings: list[str]) -> list[OpSpec]:
    meta = {
        _YAML_BOOL_KEYS.get(k, k) if isinstance(k, bool) else k: v
        for k, v in meta.items()
    }
    if verb == WRITE_ALIAS:
        if meta:
            msg = "write takes no metadata; it is a deprecated alias for create+update"
            raise OpError(msg)
        warnings.append(
            "`write` is ambiguous (create? update?); it is read as [create, update] "
            "— restate what the code does"
        )
        return [Create(), Update()]
    if verb in LEGACY_VERBS:
        fact, why = LEGACY_VERBS[verb]
        warnings.append(f"`{verb}` is read as `{fact}` ({why}); restate the fact")
        kept = {"mode": meta["mode"]} if verb == "erase" and "mode" in meta else {}
        return [_CLASSES[fact].model_validate(kept)]
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
