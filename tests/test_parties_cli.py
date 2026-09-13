"""``model-wtf compliance parties ...``: the human side of the party table."""

from __future__ import annotations

import json
import shutil
import sys
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from conftest import (
    PARTY_ACME,
    SNOW_TWO_UNITS,
    seed_activity,
    seed_party,
    seed_touchpoint,
)
from model_wtf.cli import cli
from model_wtf.compliance.activities import declared_activities
from model_wtf.compliance.declarations import load_declarations
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.party_edit import (
    merge_party,
    party_to_store,
    party_usage,
    remove_party,
    set_distinct,
    update_party,
)
from model_wtf.compliance.stamps import Holder, Stamps, read_stamps, write_stamps
from model_wtf.compliance.touchpoints import declared_touchpoints
from model_wtf.compliance.yaml_io import TODO, Marker
from test_data import FIXTURE, SNOW_DJANGO

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import MakeRepo

CODE_DIRS = ("api", "front")
EMAIL = "api:shop.Customer.email"
NAME = "api:shop.Customer.name"


@pytest.fixture
def repo(make_repo: MakeRepo) -> Path:
    """Two Sentry rows, two YouSign rows, and transfers to every one of
    them: the mess an afternoon of agents leaves behind."""
    root = make_repo(snow=SNOW_TWO_UNITS, dirs=CODE_DIRS, seed=True)
    seed_party(
        "sentry",
        **{
            **PARTY_ACME,
            "name": "Sentry",
            "website": "https://sentry.io",
            "country": "US",
        },
    )
    seed_party(
        "sentry-sdk",
        name="Sentry SDK",
        country="US",
        address=TODO,
        email=TODO,
        website="https://sentry.io",
        hosts=["o1.ingest.sentry.io"],
    )
    seed_party(
        "yousign",
        name="YouSign (Yousign SAS)",
        country="FR",
        address=TODO,
        email=TODO,
        website="https://www.yousign.com",
        hosts=["api.yousign.com"],
    )
    seed_party(
        "yousign-sa",
        name="Yousign",
        country="FR",
        address="1 rue X",
        email="dpo@yousign.com",
        website="https://yousign.com",
        hosts=["api.yousign.app"],
    )
    seed_touchpoint(
        "api",
        "checkout",
        data=[EMAIL, NAME],
        transfers=[
            {"party": "sentry", "data": [EMAIL], "purpose": "errors"},
            {"party": "yousign", "data": [NAME], "purpose": "sign"},
        ],
    )
    seed_touchpoint(
        "api",
        "sign",
        data=[EMAIL, NAME],
        transfers=[
            {"party": "sentry-sdk", "data": [NAME]},
            {"party": "yousign-sa", "data": [EMAIL, NAME]},
        ],
    )
    seed_activity(
        "signing",
        name="Signing",
        touchpoints=["api:sign"],
        recipients=["yousign-sa"],
        processor="yousign-sa",
    )
    return root


def _run(root: Path, *args: str) -> str:
    result = CliRunner().invoke(
        cli,
        ["compliance", "parties", *args, "--root", str(root)],
        env={"COLUMNS": "200"},
    )
    assert result.exit_code == 0, result.output
    return result.output


# ---------------------------------------------------------------------------
# list / show / duplicates
# ---------------------------------------------------------------------------


def test_list_and_show(repo: Path) -> None:
    out = _run(repo, "list")
    for pid in ("acme", "with-madrid", "sentry", "sentry-sdk", "yousign", "yousign-sa"):
        assert pid in out
    assert "party-duplicate" in out  # the lookalikes are reported under the table

    as_json = json.loads(_run(repo, "list", "--format", "json"))
    assert as_json["yousign-sa"]["usage"] == {
        "transfers": ["api:sign"],
        "activities": ["signing"],
        "app_roles": [],
        "distinct_in": [],
    }
    assert as_json["sentry-sdk"]["address"] == "!todo"

    unused = _run(repo, "list", "--unused")
    assert "acme" not in unused  # the app's controller
    assert "with-madrid" not in unused

    show = _run(repo, "show", "yousign-sa")
    assert "transfer api:sign" in show
    assert "activity signing" in show
    assert "api.yousign.app" in show

    result = CliRunner().invoke(
        cli, ["compliance", "parties", "show", "nope", "--root", str(repo)]
    )
    assert result.exit_code == 2
    assert "no party 'nope'" in result.output


def test_duplicates_lists_pairs_and_tests_a_candidate(repo: Path) -> None:
    result = CliRunner().invoke(
        cli,
        ["compliance", "parties", "duplicates", "--root", str(repo)],
        env={"COLUMNS": "200"},
    )
    assert result.exit_code == int(ExitCode.DECLARATION_ERROR)
    assert "sentry (Sentry)  ~  sentry-sdk" in result.output
    assert "yousign (YouSign (Yousign SAS))  ~  yousign-sa" in result.output
    assert "parties merge sentry-sdk --into sentry" in result.output

    out = _run(repo, "duplicates", "sentry-io", "--name", "Sentry.io")
    assert "lookalike sentry (Sentry; same name)" in out
    assert (
        _run(repo, "duplicates", "stripe", "--name", "Stripe")
        .strip()
        .endswith("no lookalike")
    )


# ---------------------------------------------------------------------------
# add / set / remove
# ---------------------------------------------------------------------------


def test_add_refuses_lookalikes_unless_told_and_accepts_facts(repo: Path) -> None:
    result = CliRunner().invoke(
        cli,
        ["compliance", "parties", "add", "--name", "Yousign SAS", "--root", str(repo)],
    )
    assert result.exit_code == 1
    assert "looks like an existing party" in result.output
    assert "yousign-sas" not in load_declarations().parties

    out = _run(
        repo,
        "add",
        "--name",
        "Mailjet",
        "--country",
        "FR",
        "--website",
        "https://mailjet.com",
        "--host",
        "api.mailjet.com",
    )
    assert "created  parties/mailjet" in out
    assert "still !todo: address, email" in out
    out = _run(
        repo,
        "add",
        "mailgun",
        "--name",
        "Mailgun",
        "--country",
        "US",
        "--distinct-from",
        "mailjet",
    )
    assert "created  parties/mailgun" in out
    decl = load_declarations()
    assert decl.parties["mailgun"].distinct_from == ["mailjet"]
    assert decl.parties["mailjet"].hosts == ["api.mailjet.com"]
    assert not [
        d
        for d in decl.diagnostics
        if d.code == "party-duplicate" and "mailgun" in d.message
    ]


def test_set_changes_facts_and_reopens_them(repo: Path) -> None:
    out = _run(
        repo,
        "set",
        "sentry-sdk",
        "--address",
        "45 Fremont St, San Francisco",
        "--email",
        "privacy@sentry.io",
        "--safeguard",
        "dpf",
        "--dpf-certified",
        "--host",
        "ingest.sentry.io",
    )
    assert "updated  parties/sentry-sdk" in out
    party = load_declarations().parties["sentry-sdk"]
    assert party.address == "45 Fremont St, San Francisco"
    assert party.safeguard == "dpf"
    assert party.dpf_certified is True
    assert party.hosts == ["ingest.sentry.io"]

    _run(repo, "set", "sentry-sdk", "--todo", "email", "--clear", "safeguard")
    party = load_declarations().parties["sentry-sdk"]
    assert isinstance(party.email, Marker)
    assert party.safeguard is None

    bad = CliRunner().invoke(
        cli,
        [
            "compliance",
            "parties",
            "set",
            "sentry-sdk",
            "--country",
            "usa",
            "--root",
            str(repo),
        ],
    )
    assert bad.exit_code == 2
    assert "country" in bad.output
    with pytest.raises(KeyError):
        update_party("nobody", phone="1")
    with pytest.raises(ValueError, match="unknown party fields"):
        update_party("sentry", colour="red")
    nothing = CliRunner().invoke(
        cli, ["compliance", "parties", "set", "sentry", "--root", str(repo)]
    )
    assert nothing.exit_code == 2


def test_remove_refuses_a_party_in_use_unless_forced(repo: Path) -> None:
    result = CliRunner().invoke(
        cli, ["compliance", "parties", "remove", "sentry-sdk", "--root", str(repo)]
    )
    assert result.exit_code == int(ExitCode.DECLARATION_ERROR)
    assert "in use" in result.output
    assert "transfer api:sign" in result.output
    assert "sentry-sdk" in load_declarations().parties

    seed_party("orphan", **{**PARTY_ACME, "name": "Orphan Ltd"})
    assert "removed  parties/orphan" in _run(repo, "remove", "orphan")

    out = _run(repo, "remove", "sentry-sdk", "--force")
    assert "dropped transfer api:sign" in out
    assert "sentry-sdk" not in load_declarations().parties
    sign = declared_touchpoints("api")["sign"]
    assert [t["party"] for t in sign["transfers"]] == ["yousign-sa"]

    # The app's controller is never removed this way.
    with pytest.raises(ValueError, match="app's controller"):
        remove_party("acme", force=True)


# ---------------------------------------------------------------------------
# merge / to-store / distinct
# ---------------------------------------------------------------------------


def test_merge_moves_everything_and_completes_the_winner(repo: Path) -> None:
    stamps = Stamps.model_validate({"DS06": {"status": "mitigated", "note": "x"}})
    stamps_loser = Stamps.model_validate(
        {
            "DS06": {"status": "accepted", "note": "y"},
            "DS07": {"status": "n/a", "note": "z"},
        }
    )
    write_stamps(Holder.party("yousign"), stamps)
    write_stamps(Holder.party("yousign-sa"), stamps_loser)

    out = _run(repo, "merge", "yousign-sa", "--into", "yousign")
    assert "merged  yousign-sa -> yousign" in out
    assert "moved transfer api:sign" in out
    assert "moved activity signing" in out

    decl = load_declarations()
    assert "yousign-sa" not in decl.parties
    winner = decl.parties["yousign"]
    # The winner keeps its name; its open questions take the loser's answers.
    assert winner.name == "YouSign (Yousign SAS)"
    assert winner.address == "1 rue X"
    assert winner.email == "dpo@yousign.com"
    assert sorted(winner.hosts) == ["api.yousign.app", "api.yousign.com"]

    tps = declared_touchpoints("api")
    assert [(t["party"], t["data"]) for t in tps["sign"]["transfers"]] == [
        ("sentry-sdk", [NAME]),
        ("yousign", [EMAIL, NAME]),
    ]
    assert [t["party"] for t in tps["checkout"]["transfers"]] == ["sentry", "yousign"]

    signing = declared_activities()["signing"]
    assert signing["recipients"] == ["yousign"]
    assert signing["processor"] == "yousign"

    merged = read_stamps(Holder.party("yousign"))
    assert merged.root["DS06"].status == "mitigated"  # type: ignore[union-attr]
    assert "DS07" in merged.root  # loser's added
    assert read_stamps(Holder.party("yousign-sa")).root == {}

    with pytest.raises(ValueError, match="itself"):
        merge_party("yousign", "yousign")
    with pytest.raises(KeyError):
        merge_party("nobody", "yousign")


def test_merge_when_both_transfer_from_one_touchpoint(repo: Path) -> None:
    seed_touchpoint(
        "api",
        "both",
        data=[EMAIL, NAME],
        transfers=[
            {"party": "sentry", "data": [EMAIL], "purpose": "a"},
            {"party": "sentry-sdk", "data": [NAME]},
        ],
    )
    merge_party("sentry-sdk", "sentry")
    both = declared_touchpoints("api")["both"]
    assert [(t["party"], t["data"], t.get("purpose")) for t in both["transfers"]] == [
        ("sentry", [EMAIL, NAME], "a")
    ]


def test_to_store_turns_transfers_into_writes(
    make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = make_repo(snow=SNOW_DJANGO, seed=True)
    shutil.copytree(FIXTURE, root / "api", dirs_exist_ok=True)
    monkeypatch.setenv("MODEL_WTF_PYTHON", sys.executable)
    monkeypatch.delenv("DJANGO_SETTINGS_MODULE", raising=False)
    seed_party("sentry", **{**PARTY_ACME, "name": "Sentry"})
    seed_touchpoint(
        "api",
        "checkout",
        data=[EMAIL],
        transfers=[{"party": "sentry", "data": [EMAIL], "purpose": "errors"}],
    )
    seed_activity("x", name="X", touchpoints=["api:checkout"], recipients=["sentry"])

    bad = CliRunner().invoke(
        cli,
        [
            "compliance",
            "parties",
            "to-store",
            "sentry",
            "api:nope",
            "--root",
            str(root),
        ],
    )
    assert bad.exit_code == 2
    assert "no store 'api:nope'" in bad.output

    out = _run(root, "to-store", "sentry", "api:mail-default")
    assert "moved  parties/sentry -> stores/api:mail-default" in out
    assert "sentry" not in load_declarations().parties
    checkout = declared_touchpoints("api")["checkout"]
    assert not checkout.get("transfers")
    assert [(w["store"], w["data"], w.get("purpose")) for w in checkout["stores"]] == [
        ("api:mail-default", [EMAIL], "errors")
    ]
    assert declared_activities()["x"]["recipients"] == []
    with pytest.raises(ValueError, match="app's controller"):
        party_to_store("acme", "api:mail-default")


def test_to_flow_drops_the_party_and_its_transfers(repo: Path) -> None:
    seed_party(
        "sdk", name="Project SDK endpoint", country=TODO, address=TODO, email=TODO
    )
    seed_touchpoint(
        "front",
        "/(portal)/agreements",
        data=[NAME],
        transfers=[{"party": "sdk", "data": [NAME]}],
    )
    out = _run(repo, "to-flow", "sdk")
    assert "dropped  parties/sdk" in out
    assert "dropped transfer front:/(portal)/agreements" in out
    assert "sdk" not in load_declarations().parties
    assert not declared_touchpoints("front")["/(portal)/agreements"].get("transfers")


def test_distinct_is_symmetric_and_silences_the_report(repo: Path) -> None:
    out = _run(repo, "distinct", "sentry", "sentry-sdk")
    assert "sentry is not: sentry-sdk" in out
    decl = load_declarations()
    assert decl.parties["sentry"].distinct_from == ["sentry-sdk"]
    assert decl.parties["sentry-sdk"].distinct_from == ["sentry"]
    assert not [
        d
        for d in decl.diagnostics
        if d.code == "party-duplicate" and "sentry" in d.subject  # type: ignore[operator]
    ]
    assert party_usage("sentry").distinct_in == ("sentry-sdk",)
    with pytest.raises(KeyError):
        set_distinct("sentry", ["nobody"])

    # Merging a third row into one side carries the distinction along.
    seed_party("sentry-io", name="Sentry.io", country="US", address=TODO, email=TODO)
    set_distinct("sentry-io", ["sentry-sdk"])
    merge_party("sentry-io", "sentry")
    decl = load_declarations()
    assert decl.parties["sentry"].distinct_from == ["sentry-sdk"]
    assert decl.parties["sentry-sdk"].distinct_from == ["sentry"]
