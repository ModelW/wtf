"""Rights coverage: derivation from ops, exemptions, agent verdicts, activity checks."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from conftest import FILES_ALL_OK
from model_wtf.compliance.check import run_check
from model_wtf.compliance.knowledge import load_knowledge
from model_wtf.compliance.mcp_server import Tools
from model_wtf.compliance.report import Section, Unit
from model_wtf.compliance.rights import (
    Exemption,
    Ground,
    Right,
    RightsSpec,
    RightStatus,
    rights_of,
)
from model_wtf.compliance.workspace import load_workspace
from model_wtf.compliance.yaml_io import Missing

if TYPE_CHECKING:
    from conftest import MakeRepo

FIXTURES = Path(__file__).parent / "fixtures"
SNOW = """
images:
  - id: api
    context: api
    compliance:
      discover: django
"""
EMAIL = "api:shop.Customer.email"
IBAN = "api:shop.Customer.iban"


@pytest.fixture
def repo(make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = make_repo(snow=SNOW, files=FILES_ALL_OK)
    shutil.copytree(FIXTURES / "djproj", root / "api", dirs_exist_ok=True)
    monkeypatch.setenv("MODEL_WTF_PYTHON", sys.executable)
    monkeypatch.delenv("DJANGO_SETTINGS_MODULE", raising=False)
    (root / "compliance" / "activities").mkdir()
    return root


def _ws(root: Path):
    units = [Unit("api", root / "api" / "compliance", "django", root / "api")]
    return load_workspace(root, units, load_knowledge(None))


def _tp(root: Path, slug: str, body: str) -> None:
    folder = root / "api" / "compliance" / "touchpoints"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{slug}.yaml").write_text(body)


def _activity(root: Path, slug: str, body: str) -> None:
    (root / "compliance" / "activities" / f"{slug}.yaml").write_text(body)


def _data(root: Path, stem: str, body: str) -> None:
    folder = root / "api" / "compliance" / "data"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{stem}.yaml").write_text(body)


def _status(root: Path, ref: str) -> dict[Right, tuple[RightStatus, str]]:
    item = rights_of(ref, _ws(root))
    return {f.right: (f.status, f.detail) for f in item.findings}


# ---------------------------------------------------------------------------
# schema
# ---------------------------------------------------------------------------


def test_rights_spec_vocabulary() -> None:
    spec = RightsSpec.model_validate(
        {
            "erase": {"exempt": "legal_obligation", "note": "accounting, 10 years"},
            "portability": {"exempt": "derived"},
            "rectify": Missing("nothing corrects it"),
        }
    )
    assert isinstance(spec.erase, Exemption)
    assert spec.erase.exempt is Ground.LEGAL_OBLIGATION
    assert isinstance(spec.rectify, Missing)
    with pytest.raises(ValueError, match="needs a note"):
        RightsSpec.model_validate({"erase": {"exempt": "legal_obligation"}})
    with pytest.raises(ValueError, match="only for"):
        RightsSpec.model_validate({"erase": {"exempt": "not_provided_by_subject"}})
    with pytest.raises(ValueError, match="only for"):
        RightsSpec.model_validate({"erase": {"exempt": "derived"}})
    with pytest.raises(ValueError, match="exempt"):
        RightsSpec.model_validate({"erase": {"exempt": "because"}})
    with pytest.raises(ValueError, match="Extra"):
        RightsSpec.model_validate({"erase": {"exempt": "manual", "note": "x", "z": 1}})


# ---------------------------------------------------------------------------
# derivation per item
# ---------------------------------------------------------------------------


def test_nothing_derived_without_an_activity_or_pii(repo: Path) -> None:
    _tp(repo, "checkout", f"data: [{EMAIL}, api:shop.Order.utm_campaign]\n")
    assert rights_of(EMAIL, _ws(repo)).findings == []
    _activity(
        repo,
        "ordering",
        "name: O\npurpose: p\nlegal_basis: contract\ndata_subjects: [customers]\n"
        "touchpoints: [api:checkout]\n",
    )
    # utm_campaign is behavioural (pii by the rules) but we only look at email.
    assert rights_of("api:shop.Order.utm_campaign", _ws(repo)).findings


def test_every_right_derives_from_ops(repo: Path) -> None:
    """Facts on a subject-facing touchpoint are the person's rights.

    A `read` of one's own data is access, an `update` is rectification, a
    `delete` is erasure; the reviewer never writes a legal verb.
    """
    _tp(
        repo,
        "checkout",
        f"scope: subject\ndata:\n  - {EMAIL}: create\n  - {IBAN}: create\n",
    )
    _tp(
        repo,
        "getCustomer",
        f"scope: subject\ndata:\n  - {EMAIL}: [read, update, "
        "{portability: {format: json}}]\n"
        f"  - {IBAN}: delete\n",
    )
    _tp(
        repo,
        "task__shop.purge_carts",
        f"data:\n  - {IBAN}: {{retention_purge: {{after: {{years: 1}}, "
        f"since: creation}}}}\n",
    )
    _activity(
        repo,
        "ordering",
        "name: O\npurpose: p\nlegal_basis: contract\ndata_subjects: [customers]\n"
        "touchpoints: [api:checkout, api:getCustomer, api:task:shop.purge_carts]\n",
    )

    email = _status(repo, EMAIL)
    assert email[Right.ACCESS] == (RightStatus.SATISFIED, "by api:getCustomer")
    assert email[Right.RECTIFY][0] is RightStatus.SATISFIED
    assert email[Right.PORTABILITY][0] is RightStatus.SATISFIED
    assert email[Right.ERASE] == (
        RightStatus.MISSING,
        "nothing lets the person delete it",
    )
    assert email[Right.RETENTION] == (
        RightStatus.MISSING,
        "kept forever: no purge task, nothing deletes it",
    )
    iban = _status(repo, IBAN)
    assert iban[Right.ERASE][0] is RightStatus.SATISFIED
    assert iban[Right.RETENTION] == (
        RightStatus.SATISFIED,
        "1 years after creation (api:task:shop.purge_carts)",
    )
    assert iban[Right.ACCESS] == (RightStatus.MISSING, "nothing shows it to the person")
    # Portability presupposes access: with access missing there is one gap, not two.
    assert Right.PORTABILITY not in iban

    report = run_check(repo, strict=False)
    missing = {d.subject: d for d in report.by_section()[Section.MISSING]}
    assert f"{EMAIL}#erase" in missing
    assert missing[f"{EMAIL}#erase"].code == "erasure-missing"
    assert "[derived]" in missing[f"{EMAIL}#erase"].message
    assert f"{IBAN}#erase" not in missing


def test_staff_reads_are_not_access(repo: Path) -> None:
    """The same facts on a staff screen serve no right of the person; the
    finding says staff could, so a request process can be declared."""
    _tp(repo, "admin__shop.Customer", f"data:\n  - {EMAIL}: [read, update, delete]\n")
    _tp(repo, "checkout", f"scope: public\ndata:\n  - {EMAIL}: create\n")
    _activity(
        repo,
        "ordering",
        "name: O\npurpose: p\nlegal_basis: contract\ndata_subjects: [customers]\n"
        "touchpoints: [api:checkout, api:admin:shop.Customer]\n",
    )
    status = _status(repo, EMAIL)
    assert status[Right.ACCESS][0] is RightStatus.MISSING
    assert "staff can via api:admin:shop.Customer" in status[Right.ACCESS][1]
    assert status[Right.ERASE][0] is RightStatus.MISSING
    # A staff delete still ends the row's life: storage limitation holds.
    assert status[Right.RETENTION][0] is RightStatus.SATISFIED
    ws = _ws(repo)
    assert ws.all_touchpoints["api:admin:shop.Customer"].scope.value == "staff"
    assert ws.all_touchpoints["api:checkout"].scope_declared


def test_retention_cases(repo: Path) -> None:
    """Purge cases cover some rows; the rest must end somewhere too."""
    _tp(repo, "checkout", f"scope: public\ndata:\n  - {EMAIL}: create\n")
    _tp(
        repo,
        "task__shop.purge_carts",
        f"data:\n  - {EMAIL}: {{retention_purge: {{after: settings.GUEST_MAX_AGE, "
        "since: last use, when: guest customers only}}\n",
    )
    _activity(
        repo,
        "ordering",
        "name: O\npurpose: p\nlegal_basis: contract\ndata_subjects: [customers]\n"
        "touchpoints: [api:checkout, api:task:shop.purge_carts, api:getCustomer]\n",
    )
    status = _status(repo, EMAIL)
    assert status[Right.RETENTION][0] is RightStatus.MISSING
    assert status[Right.RETENTION][1] == (
        "settings.GUEST_MAX_AGE after last use, guest customers only "
        "(api:task:shop.purge_carts); the other rows are kept forever "
        "(no purge, no delete)"
    )
    # A delete path for the others closes the gap.
    _tp(repo, "getCustomer", f"scope: subject\ndata:\n  - {EMAIL}: delete\n")
    assert _status(repo, EMAIL)[Right.RETENTION][0] is RightStatus.SATISFIED


def test_portability_needs_a_subject_facing_create(repo: Path) -> None:
    _tp(repo, "admin__shop.Customer", f"data:\n  - {EMAIL}: create\n")
    _activity(
        repo,
        "back-office",
        "name: B\npurpose: p\nlegal_basis: legitimate_interests\n"
        "data_subjects: [customers]\ntouchpoints: [api:admin:shop.Customer]\n",
    )
    status = _status(repo, EMAIL)
    assert Right.PORTABILITY not in status  # admin create, legitimate interests


# ---------------------------------------------------------------------------
# exemptions
# ---------------------------------------------------------------------------


def _ordering_with_email(repo: Path, extra_tp: str = "") -> None:
    _tp(
        repo,
        "checkout",
        f"scope: subject\ndata:\n  - {EMAIL}: create\n  - {IBAN}: create\n{extra_tp}",
    )
    _activity(
        repo,
        "ordering",
        "name: O\npurpose: p\nlegal_basis: contract\ndata_subjects: [customers]\n"
        "touchpoints: [api:checkout, api:admin:shop.Customer]\n",
    )


def test_exemptions_on_the_item(repo: Path) -> None:
    _ordering_with_email(repo)
    _data(
        repo,
        "shop.Customer.email",
        "rights:\n"
        "  erase: {exempt: legal_obligation, note: 'invoices, 10 years'}\n"
        "  retention: {exempt: legal_obligation, note: 'invoices, 10 years'}\n"
        "  portability: {exempt: not_provided_by_subject}\n"
        "  rectify: {exempt: manual, note: 'support desk'}\n"
        "  access: {exempt: staff_only}\n",
    )
    status = _status(repo, EMAIL)
    assert status[Right.ERASE][0] is RightStatus.EXEMPT
    assert "invoices" in status[Right.ERASE][1]
    assert status[Right.RECTIFY][0] is RightStatus.EXEMPT
    # staff_only is verified: no admin screen performs `access` by staff.
    assert status[Right.ACCESS][0] is RightStatus.MISSING
    assert "staff_only" in status[Right.ACCESS][1]
    # And with access missing, portability is not asked separately.
    assert Right.PORTABILITY not in status

    report = run_check(repo, strict=False)
    review = [d for d in report.diagnostics if d.code == "manual-exemption"]
    assert len(review) == 1
    assert review[0].section is Section.REVIEW
    assert "support desk" in review[0].message

    # A rights-only override file is not a classification override.
    row = _ws(repo).rows[EMAIL]
    assert row.source.value == "rule"
    assert row.rights is not None


def test_staff_only_is_verified_against_admin_ops(repo: Path) -> None:
    _ordering_with_email(repo)
    _tp(repo, "admin__shop.Customer", f"data:\n  - {EMAIL}: update\n")
    _data(repo, "shop.Customer.email", "rights:\n  rectify: {exempt: staff_only}\n")
    status = _status(repo, EMAIL)
    assert status[Right.RECTIFY][0] is RightStatus.EXEMPT
    assert "served by api:admin:shop.Customer" in status[Right.RECTIFY][1]


def test_contract_active_needs_an_end_of_contract_delete(repo: Path) -> None:
    _ordering_with_email(repo)
    _data(repo, "shop.Customer.email", "rights:\n  erase: {exempt: contract_active}\n")
    assert _status(repo, EMAIL)[Right.ERASE][0] is RightStatus.MISSING
    _tp(repo, "admin__shop.Customer", f"data:\n  - {EMAIL}: delete\n")
    status = _status(repo, EMAIL)
    assert status[Right.ERASE][0] is RightStatus.EXEMPT
    assert "removed at end of contract by" in status[Right.ERASE][1]
    # And that delete also satisfies storage limitation.
    assert status[Right.RETENTION][0] is RightStatus.SATISFIED


def test_anonymisation_needs_a_ground_to_keep_the_row(repo: Path) -> None:
    _ordering_with_email(repo)
    _tp(
        repo,
        "getCustomer",
        f"scope: subject\ndata:\n  - {EMAIL}: {{delete: {{mode: anonymise}}}}\n",
    )
    status = _status(repo, EMAIL)
    assert status[Right.ERASE][0] is RightStatus.MISSING
    assert "anonymisation without a ground" in status[Right.ERASE][1]


def test_glob_rights_file_applies_to_every_personal_field(repo: Path) -> None:
    _ordering_with_email(repo)
    _data(
        repo,
        "shop.Customer.*",
        "rights:\n  erase: {exempt: legal_claims, note: 'disputes, 5 years'}\n",
    )
    _data(
        repo,
        "shop.Customer.iban",
        "rights:\n  erase: {exempt: contract_active}\n  rectify: {exempt: derived}\n",
    )
    ws = _ws(repo)
    email_rights = ws.rows[EMAIL].rights
    assert isinstance(email_rights, RightsSpec)
    assert isinstance(email_rights.erase, Exemption)
    assert email_rights.erase.exempt is Ground.LEGAL_CLAIMS
    # The item's own file wins over the glob, right by right.
    iban_rights = ws.rows[IBAN].rights
    assert isinstance(iban_rights, RightsSpec)
    assert isinstance(iban_rights.erase, Exemption)
    assert iban_rights.erase.exempt is Ground.CONTRACT_ACTIVE
    assert isinstance(iban_rights.rectify, Exemption)
    # Non-personal fields get nothing.
    assert ws.rows["api:shop.Customer.status"].rights is None
    _data(repo, "shop.Nope.*", "rights:\n  rectify: {exempt: derived}\n")
    codes = [d.code for d in _ws(repo).data["api"].diagnostics]
    assert "data-ref-unknown" in codes


def test_rights_on_non_personal_item_is_an_error(repo: Path) -> None:
    _data(repo, "shop.Customer.status", "rights:\n  rectify: {exempt: derived}\n")
    codes = [d.code for d in _ws(repo).data["api"].diagnostics]
    assert "rights-on-non-personal" in codes


# ---------------------------------------------------------------------------
# agent verdicts: declared / claimed
# ---------------------------------------------------------------------------


def test_declared_and_claimed_missing(repo: Path) -> None:
    _ordering_with_email(repo)
    _data(repo, "shop.Customer.email", 'rights:\n  erase: !missing "no delete view"\n')
    tools = Tools(repo)
    out = tools.data_flag(
        IBAN, "retention", "missing", "purge task only logs (tasks.py:12)"
    )
    assert out == f"{IBAN}: retention missing"
    with pytest.raises(ValueError, match="not personal"):
        tools.data_flag("api:shop.Customer.status", "erase", "missing", "x")
    with pytest.raises(ValueError, match="unknown right"):
        tools.data_flag(IBAN, "forget", "missing", "x")
    with pytest.raises(ValueError, match="needs a ground"):
        tools.data_flag(IBAN, "erase", "exempt", "x")
    with pytest.raises(ValueError, match="note"):
        tools.data_flag(IBAN, "erase", "exempt", "  ", "legal_obligation")
    tools.data_flag(IBAN, "portability", "exempt", "computed", "derived")

    text = (
        repo / "api" / "compliance" / "data" / "shop.Customer.iban.yaml"
    ).read_text()
    assert "retention: !missing '[agent] purge task only logs (tasks.py:12)'" in text
    assert "portability: {exempt: derived, note: computed}" in text

    report = run_check(repo, strict=False)
    missing = {d.subject: d for d in report.by_section()[Section.MISSING]}
    assert "[declared]" in missing[f"{EMAIL}#erase"].message
    assert '"no delete view"' in missing[f"{EMAIL}#erase"].message
    assert "[claimed]" in missing[f"{IBAN}#retention"].message
    assert "purge task only logs" in missing[f"{IBAN}#retention"].message
    assert "[agent]" not in missing[f"{IBAN}#retention"].message


# ---------------------------------------------------------------------------
# activity-level checks
# ---------------------------------------------------------------------------


def test_no_pii_is_verified(repo: Path) -> None:
    _tp(repo, "getCustomer", "data: [api:shop.Order.total]\n")
    _activity(
        repo,
        "totals",
        "name: T\npurpose: p\nlegal_basis: no_pii\ndata_subjects: []\n"
        "touchpoints: [api:getCustomer]\n",
    )
    report = run_check(repo, strict=False)
    violated = [d for d in report.diagnostics if d.code == "no-pii-violated"]
    assert violated
    assert violated[0].section is Section.MISSING
    assert "api:shop.Order.total" in violated[0].message
    # No per-item rights derivation for a no_pii activity.
    assert rights_of("api:shop.Order.total", _ws(repo)).findings == []


def test_consent_proof_and_withdrawal(repo: Path) -> None:
    _tp(repo, "checkout", f"data:\n  - {EMAIL}: create\n")
    _activity(
        repo,
        "newsletter",
        "name: N\npurpose: p\nlegal_basis: consent\ndata_subjects: [customers]\n"
        "touchpoints: [api:checkout]\n",
    )
    codes = {d.code for d in run_check(repo, strict=False).diagnostics}
    assert {"consent-proof-missing", "consent-withdrawal-missing"} <= codes

    _activity(
        repo,
        "newsletter",
        "name: N\npurpose: p\nlegal_basis: consent\ndata_subjects: [customers]\n"
        f"consent: {{record: {EMAIL}, granularity: bundled}}\n"
        "touchpoints: [api:checkout, api:getCustomer]\n",
    )
    _tp(
        repo,
        "checkout",
        f"data:\n  - {EMAIL}: {{create: {{consent_for: newsletter}}}}\n",
    )
    _tp(
        repo,
        "getCustomer",
        f"data:\n  - {EMAIL}: {{consent_withdraw: {{for: newsletter}}}}\n",
    )
    diags = run_check(repo, strict=False).diagnostics
    codes = {d.code for d in diags}
    assert "consent-proof-missing" not in codes
    assert "consent-withdrawal-missing" not in codes
    assert "consent-bundled" in codes
    assert next(d for d in diags if d.code == "consent-bundled").section is Section.INFO


def test_objection_for_legitimate_interests(repo: Path) -> None:
    _tp(repo, "getCustomer", f"data: [{EMAIL}]\n")
    _activity(
        repo,
        "security",
        "name: S\npurpose: p\nlegal_basis: legitimate_interests\n"
        "data_subjects: [customers]\ntouchpoints: [api:getCustomer]\n",
    )
    report = run_check(repo, strict=False)
    assert "objection-missing" in {d.code for d in report.diagnostics}
    # The balancing test is scaffolded as a question.
    assert "security.yaml#interest" in {d.subject for d in report.diagnostics}
    # An opt-out is a subject-facing update on one of the items.
    _tp(repo, "getCustomer", f"scope: subject\ndata:\n  - {EMAIL}: [read, update]\n")
    assert "objection-missing" not in {
        d.code for d in run_check(repo, strict=False).diagnostics
    }


def test_third_country_transfer_needs_a_safeguard(repo: Path) -> None:
    tools = Tools(repo)
    tools.party_add("mapbox", "Mapbox", country="US")
    _tp(
        repo,
        "checkout",
        f"data:\n  - {EMAIL}: create\n"
        f"transfers: [{{party: mapbox, data: [{EMAIL}]}}]\n",
    )
    _activity(
        repo,
        "ordering",
        "name: O\npurpose: p\nlegal_basis: contract\ndata_subjects: [customers]\n"
        "touchpoints: [api:checkout]\n",
    )
    status = _status(repo, EMAIL)
    assert status[Right.TRANSFER][0] is RightStatus.MISSING
    assert "mapbox (US)" in status[Right.TRANSFER][1]

    # An unknown country is a question, not a finding.
    party = repo / "compliance" / "parties" / "mapbox.yaml"
    party.write_text(party.read_text().replace("country: US", "country: !todo"))
    assert _status(repo, EMAIL)[Right.TRANSFER][0] is RightStatus.UNKNOWN
    report = run_check(repo, strict=False)
    todo = {d.subject for d in report.by_section()[Section.TODO]}
    assert f"{EMAIL}#transfer" in todo
    party.write_text(party.read_text().replace("country: !todo", "country: US"))
    assert "transfer-safeguard-missing" in {
        d.code for d in run_check(repo, strict=False).diagnostics
    }

    with pytest.raises(ValueError, match="dpf_certified"):
        tools.party_add("other", "Other", country="US", safeguard="dpf")
    party.write_text(party.read_text() + "safeguard: dpf\ndpf_certified: true\n")
    status = _status(repo, EMAIL)
    assert status[Right.TRANSFER] == (RightStatus.SATISFIED, "sent to mapbox")

    # An EEA / adequacy country needs nothing.
    party.write_text(party.read_text().replace("country: US", "country: CH"))
    assert _status(repo, EMAIL)[Right.TRANSFER][0] is RightStatus.SATISFIED


def test_dpia_reference_when_the_trigger_fires(repo: Path) -> None:
    """Special-category data (``always``) is a gap; ``large_scale`` (merely
    confidential data) is a question for a human, not a finding."""
    _tp(repo, "getCustomer", f"data: [{IBAN}]\n")
    _activity(
        repo,
        "billing",
        "name: B\npurpose: p\nlegal_basis: contract\ndata_subjects: [customers]\n"
        "touchpoints: [api:getCustomer]\n",
    )
    report = run_check(repo, strict=False)
    assert "dpia-missing" not in {d.code for d in report.diagnostics}
    assert "billing.yaml#dpia_reference" in {d.subject for d in report.diagnostics}
    _tp(repo, "checkout", "data: [api:shop.Customer.allergies]\n")
    _activity(
        repo,
        "health",
        "name: H\npurpose: p\nlegal_basis: contract\ndata_subjects: [customers]\n"
        "touchpoints: [api:checkout]\n",
    )
    ws = _ws(repo)
    assert ws.activities.items["health"].derived.dpia is not None
    codes = {d.code for d in run_check(repo, strict=False).diagnostics}
    assert "dpia-missing" in codes
    _activity(
        repo,
        "health",
        "name: H\npurpose: p\nlegal_basis: contract\ndata_subjects: [customers]\n"
        "touchpoints: [api:checkout]\ndpia_reference: docs/dpia-health.md\n",
    )
    assert "dpia-missing" not in {
        d.code for d in run_check(repo, strict=False).diagnostics
    }


# ---------------------------------------------------------------------------
# activity_create verdicts
# ---------------------------------------------------------------------------


def test_activity_create_accepts_missing_verdicts(repo: Path) -> None:
    _tp(repo, "checkout", f"data:\n  - {EMAIL}: create\n")
    tools = Tools(repo)
    tools.activity_create(
        "marketing",
        "Marketing",
        "Send promotional emails",
        ["api:checkout"],
        "api.py:22",
        legal_basis={"missing": "emails sent without any opt-in (api.py:30)"},
        data_subjects=["customers"],
        basis_note="consent would apply; none is collected",
    )
    text = (repo / "compliance" / "activities" / "marketing.yaml").read_text()
    assert (
        "legal_basis: !missing '[agent] emails sent without any opt-in (api.py:30)'"
        in text
    )
    assert "basis_note: consent would apply; none is collected" in text
    assert "retention" not in text
    with pytest.raises(ValueError, match="verdict is a string"):
        tools.activity_create("x", "X", {"nope": "y"}, ["api:checkout"], "r")
    with pytest.raises(ValueError, match="not a data item"):
        tools.activity_create(
            "y",
            "Y",
            "p",
            ["api:checkout"],
            "r",
            legal_basis="consent",
            consent_record="api:shop.Nope.x",
        )
    tools.activity_create(
        "newsletter",
        "Newsletter",
        "p",
        ["api:checkout"],
        "r",
        legal_basis="consent",
        consent_record={"missing": "the opt-in is never stored"},
    )
    text = (repo / "compliance" / "activities" / "newsletter.yaml").read_text()
    assert "consent:\n  record: !missing '[agent] the opt-in is never stored'" in text

    report = run_check(repo, strict=False)
    missing = {d.subject: d for d in report.by_section()[Section.MISSING]}
    assert "marketing.yaml#legal_basis" in missing
    assert "newsletter.yaml#consent.record" in missing
