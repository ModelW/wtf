"""Pydantic schemas of the human-written compliance files.

Every field a human must provide is typed ``T | Marker`` so that a file can
be committed half-filled and ``check`` can tell "not done" from "wrong".
Optional fields are plain ``T | None`` and must be omitted, not left open:
an ``!todo`` there would be noise nobody is required to resolve.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from model_wtf.compliance.stamps import Stamps
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
    hosts: list[NonEmpty] = Field(
        default_factory=list,
        description="Hostnames (or registrable domains) this organisation "
        "operates besides its website, e.g. `api.hubapi.com` for HubSpot: a "
        "call the code makes to one of them is a transfer to this party",
    )
    registration: NonEmpty | None = Field(
        default=None, description="Company registration number"
    )
    dpo: Contact | None = Field(
        default=None, description="Art. 37 data protection officer"
    )
    representative: Contact | None = Field(
        default=None, description="Art. 27 representative in the Union"
    )
    safeguard: Literal["sccs", "bcr", "dpf", "derogation"] | Marker | None = Field(
        default=None,
        description="Ch. V safeguard for transfers to this party when it sits "
        "outside the EEA/adequacy countries: sccs, bcr, dpf or derogation",
    )
    dpf_certified: bool | None = Field(
        default=None,
        description="Whether the party is on the EU-US Data Privacy Framework list "
        "(required for safeguard: dpf)",
    )
    dpa: NonEmpty | None = Field(
        default=None,
        description="Where the data processing agreement with this party lives "
        "(URL or document reference)",
    )
    threats: Stamps = Field(
        default_factory=Stamps,
        description="Stamps closing the threat cells the matrix left open",
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
    large_scale: bool | Marker | None = Field(
        default=None,
        description="Whether the product processes personal data at large scale "
        "(Art. 35(3)(b)): true, false, or !todo while unknown. Absent means "
        "false: a DPIA is then only required for special-category data",
    )
    owners: dict[str, NonEmpty] = Field(
        default_factory=dict,
        description="GitHub handles reviewing the compliance files: `dpo` "
        "(register: activities, parties, data) and `ciso` (posture: stores, "
        "threats, the gate). Default: @<org>/dpo and @<org>/ciso",
    )


def is_valid_id(value: str) -> bool:
    """Whether ``value`` can be a file-name id."""
    return ID_RE.fullmatch(value) is not None
