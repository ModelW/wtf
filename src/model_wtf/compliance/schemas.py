"""Pydantic schemas of the human-written compliance files.

Every field a human must provide is typed ``T | Marker`` so that a file can
be committed half-filled and ``check`` can tell "not done" from "wrong".
Optional fields are plain ``T | None`` and must be omitted, not left open:
an ``!todo`` there would be noise nobody is required to resolve.
"""

from __future__ import annotations

import re
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from model_wtf.compliance.yaml_io import (
    Marker,  # noqa: TC001 - used at runtime by pydantic
)

ID_PATTERN = r"^[a-z0-9][a-z0-9-]*$"
ID_RE = re.compile(ID_PATTERN)

Slug = Annotated[str, StringConstraints(pattern=ID_PATTERN)]
CountryCode = Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}$")]
NonEmpty = Annotated[str, StringConstraints(min_length=1, strip_whitespace=True)]


class StrictModel(BaseModel):
    """Base for all compliance files: unknown keys are errors, not typos."""

    model_config = ConfigDict(extra="forbid")


class Contact(StrictModel):
    """A named person or office reachable by email (DPO, representative)."""

    name: NonEmpty | Marker = Field(description="Who to name as the contact")
    email: NonEmpty | Marker = Field(description="Address the contact answers at")
    phone: NonEmpty | None = None


class Party(StrictModel):
    """One organisation in ``compliance/parties/<id>.yaml``.

    Controller, processor or recipient is a *role* an organisation plays in
    a given processing activity, so parties are role-less here; the roles
    are declared where the processing is.
    """

    name: NonEmpty | Marker = Field(description="Legal name of the organisation")
    country: CountryCode | Marker = Field(
        description="Country of establishment (ISO 3166-1 alpha-2); drives the "
        "third-country transfer logic"
    )
    address: NonEmpty | Marker = Field(description="Postal address of the seat")
    email: NonEmpty | Marker = Field(
        description="Email for privacy matters (the one to put in a notice)"
    )
    phone: NonEmpty | None = None
    website: NonEmpty | None = None
    registration: NonEmpty | None = Field(
        default=None, description="Company registration number"
    )
    dpo: Contact | None = Field(
        default=None, description="Art. 37 data protection officer"
    )
    representative: Contact | None = Field(
        default=None, description="Art. 27 representative in the Union"
    )


class App(StrictModel):
    """``compliance/app.yaml``: what the product is and who answers for it.

    The usual typology is a client (controller) commissioning the agency
    (processor), so both are normally filled; ``processor`` is omitted only
    when the controller runs the product itself.
    """

    name: NonEmpty | Marker = Field(description="Name of the product")
    description: NonEmpty | Marker = Field(
        description="What the product does, for whom, in a few sentences"
    )
    controller: Slug | Marker = Field(description="Party id of the controller")
    processor: Slug | Marker | None = Field(
        default=None, description="Party id of the processor, if any"
    )


def is_valid_id(value: str) -> bool:
    """Whether ``value`` can be a file-name id."""
    return ID_RE.fullmatch(value) is not None
