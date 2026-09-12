"""The schema of ``compliance.db``, as SQLAlchemy mapped classes.

Everything a human or an agent declares about the repository lives here;
what the code says (models, routes, stores from the settings) is
introspected on every run and never stored. Tables are normalised where
rows get cross-referenced (hosts, refs, transfers, stamps, locks, the
findings register); genuinely nested shapes (op payloads, challenge blocks,
contact blocks, rights specs) are JSON columns.

Every value a human still has to provide is a :class:`Human` column: a
JSON-encoded scalar that may also be a ``!todo`` / ``!missing`` marker
(see :mod:`model_wtf.compliance.yaml_io`), so a row can be committed
half-filled and ``check`` can tell "not done" from "wrong".
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, ClassVar

from sqlalchemy import (
    JSON,
    Boolean,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from model_wtf.compliance.yaml_io import Marker, Missing, Todo

if TYPE_CHECKING:
    from sqlalchemy.engine.interfaces import Dialect

MARKER_KEYS = {"todo": Todo, "missing": Missing}


def encode_human(value: object) -> object:
    """Marker → ``{"todo": note}`` / ``{"missing": note}``, recursively through
    mappings and lists; anything else as is."""
    if isinstance(value, Marker):
        return {value.tag.lstrip("!"): value.note}
    if isinstance(value, dict):
        return {str(k): encode_human(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [encode_human(v) for v in value]
    return value


def decode_human(raw: object) -> object:
    """Inverse of :func:`encode_human`."""
    if isinstance(raw, dict):
        if len(raw) == 1:
            ((key, note),) = raw.items()
            cls = MARKER_KEYS.get(str(key))
            if cls is not None and (note is None or isinstance(note, str)):
                return cls(note)
        return {str(k): decode_human(v) for k, v in raw.items()}
    if isinstance(raw, list):
        return [decode_human(v) for v in raw]
    return raw


class Human(TypeDecorator[Any]):
    """A JSON value (scalar, list or mapping) in which any leaf may be a
    ``!todo`` / ``!missing`` marker."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: object, dialect: Dialect) -> str | None:
        """Serialise for storage."""
        if value is None:
            return None
        return json.dumps(encode_human(value), ensure_ascii=False)

    def process_result_value(self, value: object, dialect: Dialect) -> object:
        """Deserialise on read."""
        if value is None:
            return None
        return decode_human(json.loads(str(value)))


class Base(DeclarativeBase):
    """Declarative base of every table."""

    type_annotation_map: ClassVar[dict[Any, Any]] = {
        dict[str, Any]: JSON,
        list[Any]: JSON,
    }


class AppRow(Base):
    """The one product row: what it is and who answers for it."""

    __tablename__ = "app"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    name: Mapped[str | Marker] = mapped_column(Human)
    description: Mapped[str | Marker] = mapped_column(Human)
    controller: Mapped[str | Marker] = mapped_column(Human)
    processor: Mapped[str | Marker | None] = mapped_column(Human, nullable=True)
    large_scale: Mapped[bool | Marker | None] = mapped_column(Human, nullable=True)


class PartyRow(Base):
    """One organisation (roles are declared per activity, not here)."""

    __tablename__ = "parties"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str | Marker] = mapped_column(Human)
    country: Mapped[str | Marker] = mapped_column(Human)
    address: Mapped[str | Marker] = mapped_column(Human)
    email: Mapped[str | Marker] = mapped_column(Human)
    phone: Mapped[str | None] = mapped_column(Text, nullable=True)
    website: Mapped[str | None] = mapped_column(Text, nullable=True)
    registration: Mapped[str | None] = mapped_column(Text, nullable=True)
    dpo: Mapped[dict[str, Any] | None] = mapped_column(Human, nullable=True)
    representative: Mapped[dict[str, Any] | None] = mapped_column(Human, nullable=True)
    safeguard: Mapped[str | Marker | None] = mapped_column(Human, nullable=True)
    dpf_certified: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    dpa: Mapped[str | None] = mapped_column(Text, nullable=True)

    hosts: Mapped[list[PartyHostRow]] = relationship(
        cascade="all, delete-orphan", order_by="PartyHostRow.host"
    )


class PartyHostRow(Base):
    """A hostname (or settings name) a party operates."""

    __tablename__ = "party_hosts"

    party_id: Mapped[str] = mapped_column(
        ForeignKey("parties.id", ondelete="CASCADE"), primary_key=True
    )
    host: Mapped[str] = mapped_column(Text, primary_key=True)


class StoreRow(Base):
    """A declared store of a unit: an override of an introspected one, or a
    manual one (``type`` given) the settings do not show."""

    __tablename__ = "stores"

    unit: Mapped[str] = mapped_column(Text, primary_key=True)
    slug: Mapped[str] = mapped_column(Text, primary_key=True)
    type: Mapped[str | None] = mapped_column(Text, nullable=True)
    backend: Mapped[str | None] = mapped_column(Text, nullable=True)
    name: Mapped[str | Marker | None] = mapped_column(Human, nullable=True)
    provider: Mapped[str | Marker | None] = mapped_column(Human, nullable=True)
    location: Mapped[str | Marker | None] = mapped_column(Human, nullable=True)
    retention: Mapped[str | Marker | None] = mapped_column(Human, nullable=True)
    description: Mapped[str | Marker | None] = mapped_column(Human, nullable=True)
    ignore: Mapped[bool] = mapped_column(Boolean, default=False)

    hosts: Mapped[list[StoreHostRow]] = relationship(
        cascade="all, delete-orphan", order_by="StoreHostRow.host"
    )


class StoreHostRow(Base):
    """A hostname / settings name the code reaches a store at."""

    __tablename__ = "store_hosts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["unit", "slug"], ["stores.unit", "stores.slug"], ondelete="CASCADE"
        ),
    )

    unit: Mapped[str] = mapped_column(Text, primary_key=True)
    slug: Mapped[str] = mapped_column(Text, primary_key=True)
    host: Mapped[str] = mapped_column(Text, primary_key=True)


class DataItemRow(Base):
    """What a human wrote about one data item.

    ``kind`` is ``override`` (a field the code knows), ``manual`` (an item
    the code does not expose), ``contents`` (a JSON-like column's
    declaration, see :class:`DataContentRow`) or ``rights`` (a
    ``<app.Model>.*`` glob carrying a rights block for a whole model).
    """

    __tablename__ = "data_items"

    unit: Mapped[str] = mapped_column(Text, primary_key=True)
    id: Mapped[str] = mapped_column(Text, primary_key=True)
    kind: Mapped[str] = mapped_column(Text)
    pii: Mapped[bool | Marker | None] = mapped_column(Human, nullable=True)
    sensitivity: Mapped[str | Marker | None] = mapped_column(Human, nullable=True)
    category: Mapped[str | Marker | None] = mapped_column(Human, nullable=True)
    store: Mapped[str | Marker | None] = mapped_column(Human, nullable=True)
    reason: Mapped[str | Marker | None] = mapped_column(Human, nullable=True)
    description: Mapped[str | Marker | None] = mapped_column(Human, nullable=True)
    transient: Mapped[bool] = mapped_column(Boolean, default=False)
    unknown_contents: Mapped[str | None] = mapped_column(Text, nullable=True)
    rights: Mapped[dict[str, Any] | None] = mapped_column(Human, nullable=True)

    contents: Mapped[list[DataContentRow]] = relationship(
        cascade="all, delete-orphan", order_by="DataContentRow.position"
    )


class DataContentRow(Base):
    """One kind of information held in a container column."""

    __tablename__ = "data_contents"
    __table_args__ = (
        ForeignKeyConstraint(
            ["unit", "item_id"],
            ["data_items.unit", "data_items.id"],
            ondelete="CASCADE",
        ),
    )

    unit: Mapped[str] = mapped_column(Text, primary_key=True)
    item_id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text, primary_key=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    pii: Mapped[bool | Marker] = mapped_column(Human)
    sensitivity: Mapped[str | Marker] = mapped_column(Human)
    category: Mapped[str | Marker] = mapped_column(Human)


class DataLockRow(Base):
    """The review of one data item (the former ``data.lock.yaml`` entry)."""

    __tablename__ = "data_locks"

    unit: Mapped[str] = mapped_column(Text, primary_key=True)
    item_id: Mapped[str] = mapped_column(Text, primary_key=True)
    fingerprint: Mapped[str] = mapped_column(Text)
    reviewed_at: Mapped[str] = mapped_column(Text)
    commit: Mapped[str | None] = mapped_column(Text, nullable=True)
    by: Mapped[str] = mapped_column(Text)
    model: Mapped[str | None] = mapped_column(Text, nullable=True)
    note: Mapped[str] = mapped_column(Text, default="")
    challenge: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    answered: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)


class TouchpointRow(Base):
    """A touchpoint's declaration (the former manifest)."""

    __tablename__ = "touchpoints"

    unit: Mapped[str] = mapped_column(Text, primary_key=True)
    id: Mapped[str] = mapped_column(Text, primary_key=True)
    declared: Mapped[bool] = mapped_column(Boolean, default=False)
    """Whether ``data`` was given (an empty list is a valid declaration)."""
    scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    ignore: Mapped[bool] = mapped_column(Boolean, default=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    challenge: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    answered: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    data: Mapped[list[TouchpointDataRow]] = relationship(
        cascade="all, delete-orphan", order_by="TouchpointDataRow.position"
    )
    transfers: Mapped[list[TransferRow]] = relationship(
        cascade="all, delete-orphan", order_by="TransferRow.position"
    )
    store_writes: Mapped[list[StoreWriteRow]] = relationship(
        cascade="all, delete-orphan", order_by="StoreWriteRow.position"
    )
    undeclared: Mapped[list[UndeclaredRow]] = relationship(
        cascade="all, delete-orphan", order_by="UndeclaredRow.position"
    )


_TP_FK = ("touchpoints.unit", "touchpoints.id")


class TouchpointDataRow(Base):
    """One data ref (``unit:id`` or a glob) a touchpoint handles, with its ops."""

    __tablename__ = "touchpoint_data"
    __table_args__ = (
        ForeignKeyConstraint(["unit", "touchpoint_id"], _TP_FK, ondelete="CASCADE"),
    )

    unit: Mapped[str] = mapped_column(Text, primary_key=True)
    touchpoint_id: Mapped[str] = mapped_column(Text, primary_key=True)
    ref: Mapped[str] = mapped_column(Text, primary_key=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    ops: Mapped[list[Any]] = mapped_column(JSON)
    """``[{"op": verb, ...metadata}]`` (the tool form of :mod:`ops`)."""


class TransferRow(Base):
    """What a touchpoint sends to another organisation."""

    __tablename__ = "touchpoint_transfers"
    __table_args__ = (
        ForeignKeyConstraint(["unit", "touchpoint_id"], _TP_FK, ondelete="CASCADE"),
    )

    unit: Mapped[str] = mapped_column(Text, primary_key=True)
    touchpoint_id: Mapped[str] = mapped_column(Text, primary_key=True)
    party_id: Mapped[str] = mapped_column(
        ForeignKey("parties.id", ondelete="CASCADE"), primary_key=True
    )
    position: Mapped[int] = mapped_column(Integer, default=0)
    data: Mapped[list[Any]] = mapped_column(JSON)
    """Full ids of what is sent."""
    purpose: Mapped[str | None] = mapped_column(Text, nullable=True)


class StoreWriteRow(Base):
    """What a touchpoint copies into another store of the project."""

    __tablename__ = "touchpoint_store_writes"
    __table_args__ = (
        ForeignKeyConstraint(["unit", "touchpoint_id"], _TP_FK, ondelete="CASCADE"),
    )

    unit: Mapped[str] = mapped_column(Text, primary_key=True)
    touchpoint_id: Mapped[str] = mapped_column(Text, primary_key=True)
    store: Mapped[str] = mapped_column(Text, primary_key=True)
    """``unit:slug`` of the store written to."""
    position: Mapped[int] = mapped_column(Integer, default=0)
    data: Mapped[list[Any]] = mapped_column(JSON)
    purpose: Mapped[str | None] = mapped_column(Text, nullable=True)


class UndeclaredRow(Base):
    """A flow a reviewer found in the code that the declaration lacks."""

    __tablename__ = "touchpoint_undeclared"
    __table_args__ = (
        ForeignKeyConstraint(["unit", "touchpoint_id"], _TP_FK, ondelete="CASCADE"),
    )

    unit: Mapped[str] = mapped_column(Text, primary_key=True)
    touchpoint_id: Mapped[str] = mapped_column(Text, primary_key=True)
    sink: Mapped[str] = mapped_column(Text, primary_key=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    data: Mapped[list[Any]] = mapped_column(JSON)
    note: Mapped[str] = mapped_column(Text)
    commit: Mapped[str | None] = mapped_column(Text, nullable=True)
    at: Mapped[str | None] = mapped_column(Text, nullable=True)


class StampRow(Base):
    """One threat stamp: a verdict, a weighed finding or a bare ``!missing``
    on one element (``holder``) for one ``key`` (``SID`` or ``SID@sink``)."""

    __tablename__ = "threat_stamps"

    holder_kind: Mapped[str] = mapped_column(Text, primary_key=True)
    """``touchpoint``, ``store`` or ``party``."""
    holder_unit: Mapped[str] = mapped_column(Text, primary_key=True, default="")
    """The unit for touchpoints and stores; empty for parties."""
    holder_id: Mapped[str] = mapped_column(Text, primary_key=True)
    key: Mapped[str] = mapped_column(Text, primary_key=True)
    kind: Mapped[str] = mapped_column(Text)
    """``stamp``, ``finding`` or ``missing``."""
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class ActivityRow(Base):
    """A GDPR processing activity: the register's row."""

    __tablename__ = "activities"

    slug: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str | Marker] = mapped_column(Human)
    purpose: Mapped[str | Marker] = mapped_column(Human)
    legal_basis: Mapped[str | Marker] = mapped_column(Human)
    basis_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    consent_record: Mapped[str | Marker | None] = mapped_column(Human, nullable=True)
    consent_granularity: Mapped[str | None] = mapped_column(Text, nullable=True)
    interest: Mapped[str | Marker | None] = mapped_column(Human, nullable=True)
    dpia_reference: Mapped[str | Marker | None] = mapped_column(Human, nullable=True)
    data_subjects: Mapped[list[str] | Marker] = mapped_column(Human)
    retention: Mapped[str | Marker | None] = mapped_column(Human, nullable=True)
    controller: Mapped[str | Marker | None] = mapped_column(Human, nullable=True)
    processor: Mapped[str | Marker | None] = mapped_column(Human, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    touchpoints: Mapped[list[ActivityTouchpointRow]] = relationship(
        cascade="all, delete-orphan", order_by="ActivityTouchpointRow.position"
    )
    recipients: Mapped[list[ActivityRecipientRow]] = relationship(
        cascade="all, delete-orphan", order_by="ActivityRecipientRow.party_id"
    )


class ActivityTouchpointRow(Base):
    """A touchpoint an activity groups."""

    __tablename__ = "activity_touchpoints"

    slug: Mapped[str] = mapped_column(
        ForeignKey("activities.slug", ondelete="CASCADE"), primary_key=True
    )
    unit: Mapped[str] = mapped_column(Text, primary_key=True)
    touchpoint_id: Mapped[str] = mapped_column(Text, primary_key=True)
    position: Mapped[int] = mapped_column(Integer, default=0)


class ActivityRecipientRow(Base):
    """A declared recipient of an activity."""

    __tablename__ = "activity_recipients"

    slug: Mapped[str] = mapped_column(
        ForeignKey("activities.slug", ondelete="CASCADE"), primary_key=True
    )
    party_id: Mapped[str] = mapped_column(Text, primary_key=True)


class FindingRow(Base):
    """The findings register: ``F-0001`` → its natural key."""

    __tablename__ = "findings"

    fid: Mapped[str] = mapped_column(Text, primary_key=True)
    key: Mapped[str] = mapped_column(Text, unique=True)
    opened: Mapped[str] = mapped_column(Text)
    closed: Mapped[str | None] = mapped_column(Text, nullable=True)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)


class ActorRow(Base):
    """A project override of a threat actor's malice / reach."""

    __tablename__ = "actors"

    name: Mapped[str] = mapped_column(Text, primary_key=True)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    malice: Mapped[float | None] = mapped_column(Float, nullable=True)
    reach: Mapped[float | None] = mapped_column(Float, nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)


class SensitivityRow(Base):
    """A project's own sensitivity level (replaces the built-in scale)."""

    __tablename__ = "sensitivity_levels"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    rank: Mapped[int] = mapped_column(Integer)
    description: Mapped[str | Marker] = mapped_column(Human)
    criteria: Mapped[str | Marker] = mapped_column(Human)
    handling: Mapped[str | Marker] = mapped_column(Human)
    dpia: Mapped[str] = mapped_column(Text, default="never")
    replaces: Mapped[list[Any]] = mapped_column(JSON, default=list)


class CategoryRow(Base):
    """A project's own category of personal data."""

    __tablename__ = "categories"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    description: Mapped[str | Marker] = mapped_column(Human)
    examples: Mapped[list[Any]] = mapped_column(JSON, default=list)
    register_label: Mapped[str | Marker] = mapped_column(Human)
    legal: Mapped[str] = mapped_column(Text, default="none")
    dpia: Mapped[bool] = mapped_column(Boolean, default=False)
    replaces: Mapped[list[Any]] = mapped_column(JSON, default=list)


__all__ = [
    "ActivityRecipientRow",
    "ActivityRow",
    "ActivityTouchpointRow",
    "ActorRow",
    "AppRow",
    "Base",
    "CategoryRow",
    "DataContentRow",
    "DataItemRow",
    "DataLockRow",
    "FindingRow",
    "Human",
    "PartyHostRow",
    "PartyRow",
    "SensitivityRow",
    "StampRow",
    "StoreHostRow",
    "StoreRow",
    "StoreWriteRow",
    "TouchpointDataRow",
    "TouchpointRow",
    "TransferRow",
    "UndeclaredRow",
    "decode_human",
    "encode_human",
]
