"""The duplicate-party guard: matching rules, the writer, ``check``, ``init``."""

from __future__ import annotations

import shutil
import sys
from typing import TYPE_CHECKING

import pytest

from conftest import PARTY_ACME, SNOW_TWO_UNITS, seed_party
from model_wtf.compliance.declarations import (
    DuplicateParty,
    load_declarations,
    save_party,
)
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.init_cmd import InitError, PartySpec, run_init
from model_wtf.compliance.mcp_server import Tools
from model_wtf.compliance.parties import (
    PartyFingerprint,
    find_lookalikes,
    names_alike,
    normalise_name,
    registrable_domain,
)

if TYPE_CHECKING:
    from conftest import MakeRepo

CODE_DIRS = ("api", "front")


# ---------------------------------------------------------------------------
# pure matching
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Mapbox, Inc.", "mapbox"),
        ("Société Générale S.A.", "societe generale"),
        ("WITH Madrid S.L.", "with madrid"),
        ("Sentry.io", "sentry"),
        ("Microsoft Ireland Operations Ltd", "microsoft ireland operations"),
        ("The Company", "the company"),  # nothing else left: keep the words
        ("  HubSpot  ", "hubspot"),
    ],
)
def test_normalise_name(raw: str, expected: str) -> None:
    assert normalise_name(raw) == expected


@pytest.mark.parametrize(
    ("a", "b", "alike"),
    [
        ("Mapbox", "Mapbox, Inc.", True),  # legal form
        ("Société Générale", "societe generale SA", True),  # accents, case
        ("HubSpot", "HubSpot Europe", True),  # a word added
        ("Google", "Google Cloud", True),
        ("Scaleway", "Scalway", True),  # typo in a long name
        ("Intercom", "Interco", True),
        ("Hub Spot", "HubSpot", True),  # spacing
        ("OVH", "OVO", False),  # short names: exact only
        ("Stripe", "Strip", False),
        ("Brevo", "Bravo", False),
        ("Mailgun", "Mailjet", False),  # two real companies
        ("Adyen", "Ayden", False),
        ("Amazon Web Services", "AWS", False),  # acronyms are out of scope
        ("ACME Corp", "WITH Madrid SL", False),
        ("", "Mapbox", False),  # a !todo name matches nothing
    ],
)
def test_names_alike(a: str, b: str, alike: bool) -> None:
    assert names_alike(normalise_name(a), normalise_name(b)) is alike


def test_registrable_domain() -> None:
    assert registrable_domain("https://api.hubapi.com/v3") == "hubapi.com"
    assert registrable_domain("api.mapbox.com:443") == "mapbox.com"
    assert registrable_domain("mapbox.com") == "mapbox.com"
    assert registrable_domain("MAILGUN_API_URL") == "mailgun_api_url"


def test_fingerprint_reasons() -> None:
    mapbox = PartyFingerprint.of("mapbox", "Mapbox", "https://mapbox.com")
    by_name = PartyFingerprint.of("cartography", "Mapbox, Inc.")
    by_domain = PartyFingerprint.of(
        "cartography", "Cartography Co", hosts=["api.mapbox.com"]
    )
    by_id = PartyFingerprint.of("map-box", "Some Maps")
    other = PartyFingerprint.of("stripe", "Stripe", "https://stripe.com")

    assert mapbox.lookalike_of(by_name) is not None
    assert mapbox.lookalike_of(by_name).reason == "name"  # type: ignore[union-attr]
    assert mapbox.lookalike_of(by_domain).reason == "domain mapbox.com"  # type: ignore[union-attr]
    assert mapbox.lookalike_of(by_id).reason == "id"  # type: ignore[union-attr]
    assert mapbox.lookalike_of(other) is None
    # A settings name in hosts is shared like a domain: two parties reached
    # through one ERP_API_BASE_URL are one party.
    setting = PartyFingerprint.of("erp", "Client ERP", hosts=["ERP_API_BASE_URL"])
    same = PartyFingerprint.of("payroll", "Payroll API", hosts=["erp_api_base_url"])
    assert setting.lookalike_of(same).reason == "domain erp_api_base_url"  # type: ignore[union-attr]
    # A wildcard host resolves to its registrable domain.
    wild = PartyFingerprint.of("x", "X", hosts=["*.ingest.sentry.io"])
    assert wild.domains == frozenset({"sentry.io"})


def test_find_lookalikes_ignores_self_and_reads_the_database(
    make_repo: MakeRepo,
) -> None:
    make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)
    seed_party("mapbox", **{**PARTY_ACME, "name": "Mapbox", "website": "mapbox.com"})

    hits = find_lookalikes("mapbox-inc", {"name": "Mapbox, Inc."})
    assert [h.party_id for h in hits] == ["mapbox"]
    assert find_lookalikes("mapbox", {"name": "Mapbox"}) == []  # itself
    assert find_lookalikes("stripe", {"name": "Stripe"}) == []


# ---------------------------------------------------------------------------
# the writer
# ---------------------------------------------------------------------------


def test_save_party_refuses_a_lookalike(make_repo: MakeRepo) -> None:
    make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)
    seed_party(
        "hubspot",
        **{**PARTY_ACME, "name": "HubSpot", "hosts": ["api.hubapi.com"]},
    )

    with pytest.raises(DuplicateParty) as info:
        save_party("hubspot-inc", {**PARTY_ACME, "name": "HubSpot, Inc."})
    assert [x.party_id for x in info.value.lookalikes] == ["hubspot"]
    assert "same name" in str(info.value)
    assert "parties add hubspot-inc ... --distinct-from hubspot" in str(info.value)
    assert "hubspot-inc" not in load_declarations().parties

    # Same organisation reached through its API domain, under another name.
    with pytest.raises(DuplicateParty, match=r"domain hubapi\.com"):
        save_party(
            "crm",
            {**PARTY_ACME, "name": "Our CRM vendor", "hosts": ["eu1.hubapi.com"]},
        )

    # A stated distinction goes through and is stored.
    assert save_party(
        "hubspot-europe",
        {**PARTY_ACME, "name": "HubSpot Europe", "distinct_from": ["hubspot"]},
    )
    assert load_declarations().parties["hubspot-europe"].distinct_from == ["hubspot"]


def test_save_party_still_reports_an_existing_id_as_such(make_repo: MakeRepo) -> None:
    make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)
    # Same id, same name: not a duplicate, the row exists (init is idempotent).
    assert save_party("acme", PARTY_ACME) is False


# ---------------------------------------------------------------------------
# the tool
# ---------------------------------------------------------------------------


def test_party_add_tool_explains_the_refusal(make_repo: MakeRepo) -> None:
    make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)
    tools = Tools()
    assert "created party mapbox" in tools.party_add(
        "mapbox", "Mapbox", website="https://mapbox.com", country="US"
    )

    # Final for the agent: no distinct_from argument to slip through.
    with pytest.raises(ValueError, match="looks like an existing party: mapbox"):
        tools.party_add("mapbox-inc", "Mapbox, Inc.", country="US")
    with pytest.raises(TypeError):
        tools.party_add("mapbox-inc", "Mapbox, Inc.", distinct_from=["mapbox"])  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# a party that is a store
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("party_id", "spec", "reason"),
    [
        ("sentry", {"name": "Sentry", "website": "https://sentry.io"}, "same name"),
        ("sentry-sdk", {"name": "Sentry SDK ingest"}, "same name"),
        ("smtp", {"name": "SMTP mail server"}, "same kind mail"),
        ("resend", {"name": "Resend", "hosts": ["EMAIL_HOST"]}, "same host email_host"),
    ],
)
def test_store_clashes(party_id: str, spec: dict[str, object], reason: str) -> None:
    from model_wtf.compliance.parties import store_clashes
    from model_wtf.compliance.stores import Store, StoreSource, StoreType

    stores = [
        Store(
            unit="api",
            slug="mail-default",
            type=StoreType.MAIL,
            source=StoreSource.CONFIG,
            backend="email",
            hosts=("EMAIL_BACKEND", "EMAIL_HOST"),
        ),
        Store(
            unit="api",
            slug="errors-sentry",
            type=StoreType.MONITORING,
            source=StoreSource.CONFIG,
            backend="sentry",
            hosts=("sentry_sdk", "SENTRY_DSN"),
        ),
        Store(
            unit="api",
            slug="files-default",
            type=StoreType.BUCKET,
            source=StoreSource.CONFIG,
            backend="s3",
        ),
    ]
    hits = store_clashes(party_id, spec, stores)
    slug = "mail-default" if "mail" in reason else "errors-sentry"
    assert [str(h) for h in hits] == [f"store api:{slug} ({reason})"]
    # Generic words never make a party a store: "Files Ltd" is a company.
    assert store_clashes("files", {"name": "Files Ltd"}, stores) == []
    assert (
        store_clashes("stripe", {"name": "Stripe", "hosts": ["api.stripe.com"]}, stores)
        == []
    )


def test_party_add_refuses_a_store(
    make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    from model_wtf.compliance.declarations import PartyIsAStore
    from test_data import FIXTURE, SNOW_DJANGO

    root = make_repo(snow=SNOW_DJANGO, seed=True)
    shutil.copytree(FIXTURE, root / "api", dirs_exist_ok=True)
    monkeypatch.setenv("MODEL_WTF_PYTHON", sys.executable)
    monkeypatch.delenv("DJANGO_SETTINGS_MODULE", raising=False)
    tools = Tools()
    with pytest.raises(PartyIsAStore, match="store api:mail-default"):
        tools.party_add("mailgun", "Mailgun", hosts=["EMAIL_HOST"])
    assert "mailgun" not in load_declarations().parties


# ---------------------------------------------------------------------------
# check and init
# ---------------------------------------------------------------------------


def test_check_reports_coexisting_lookalikes(make_repo: MakeRepo) -> None:
    make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)
    seed_party("mapbox", **{**PARTY_ACME, "name": "Mapbox"})
    seed_party("mapbox-inc", **{**PARTY_ACME, "name": "Mapbox, Inc."})

    decl = load_declarations()
    dups = [d for d in decl.diagnostics if d.code == "party-duplicate"]
    assert len(dups) == 1
    assert dups[0].subject == "parties/mapbox+mapbox-inc"
    assert "same name" in dups[0].message
    assert decl.has_errors

    from model_wtf.compliance.check import run_check

    assert run_check(strict=False).exit_code is ExitCode.DECLARATION_ERROR

    # Either side may carry the distinction.
    seed_party(
        "mapbox", **{**PARTY_ACME, "name": "Mapbox", "distinct_from": ["mapbox-inc"]}
    )
    assert not [
        d for d in load_declarations().diagnostics if d.code == "party-duplicate"
    ]


def test_init_refuses_a_respelled_party(make_repo: MakeRepo) -> None:
    make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS)
    run_init(
        app_name="x",
        controller=PartySpec(name="ACME Corp", country="FR"),
        processor=None,
    )

    with pytest.raises(InitError, match="looks like an existing party: acme-corp"):
        run_init(
            app_name="x",
            controller=PartySpec(name="ACME Corporation", country="FR"),
            processor=None,
        )
    assert list(load_declarations().parties) == ["acme-corp"]
