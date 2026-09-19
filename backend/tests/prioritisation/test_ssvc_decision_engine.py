import pytest

from app.prioritisation.ssvc_decision_engine import SSVCDecisionEngine


# BOD 26-04 Table 1: Remediation Timelines (16 rows, verbatim), keyed by
# (publicly_exposed, in_kev, automatable, total_control).
# https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk
@pytest.mark.parametrize("exposed,in_kev,automatable,total_control,expected_outcome,expected_days,expected_forensic", [
    (True,  True,  True,  True,  "immediate",    3,    True),   # row 1
    (True,  True,  True,  False, "immediate",    3,    False),  # row 2
    (True,  True,  False, True,  "immediate",    3,    True),   # row 3
    (True,  True,  False, False, "out-of-cycle", 14,   False),  # row 4
    (True,  False, True,  True,  "immediate",    3,    False),  # row 5
    (True,  False, True,  False, "out-of-cycle", 14,   False),  # row 6
    (True,  False, False, True,  "out-of-cycle", 14,   False),  # row 7
    (True,  False, False, False, "scheduled",    60,   False),  # row 8
    (False, True,  True,  True,  "immediate",    3,    True),   # row 9
    (False, True,  True,  False, "out-of-cycle", 14,   False),  # row 10
    (False, True,  False, True,  "out-of-cycle", 14,   False),  # row 11
    (False, True,  False, False, "out-of-cycle", 14,   False),  # row 12
    (False, False, True,  True,  "scheduled",    60,   False),  # row 13
    (False, False, True,  False, "scheduled",    60,   False),  # row 14
    (False, False, False, True,  "defer",        None, False),  # row 15
    (False, False, False, False, "defer",        None, False),  # row 16
], ids=lambda v: str(v))
def test_compute_decision_matches_bod_26_04_table_1(exposed, in_kev, automatable, total_control, expected_outcome,
                                                      expected_days, expected_forensic, make_asset,
                                                      make_vulnerability):
    asset = make_asset(internet_facing=exposed)
    vuln = make_vulnerability(in_kev=in_kev,
                               automatable="yes" if automatable else "no",
                               technical_impact="total" if total_control else "partial")

    result = SSVCDecisionEngine().compute(asset, vuln)

    assert result["ssvc_decision"] == expected_outcome
    assert result["remediation_days"] == expected_days
    assert result["forensic_triage_required"] == expected_forensic


def test_compute_returns_full_expected_dict_shape(make_asset, make_vulnerability):
    asset = make_asset(asset_id="asset-42", internet_facing=True)
    vuln = make_vulnerability(cve_id="CVE-2024-9999", in_kev=True, automatable="yes", technical_impact="total")

    result = SSVCDecisionEngine().compute(asset, vuln)

    assert result == {
        "asset_id": "asset-42",
        "cve_id": "CVE-2024-9999",
        "ssvc_decision": "immediate",
        "remediation_days": 3,
        "forensic_triage_required": True,
        "publicly_exposed": True,
        "in_kev": True,
        "automatable": True,
        "technical_impact": "total",
        "reasoning": (
            "BOD 26-04 Table 1: publicly exposed=True, in KEV=True, automatable=True, "
            "technical impact=total -> 3-day remediation with forensic triage."
        ),
    }


def test_compute_reasoning_for_defer_mentions_system_upgrade(make_asset, make_vulnerability):
    asset = make_asset(internet_facing=False)
    vuln = make_vulnerability(in_kev=False, automatable="no", technical_impact="partial")

    result = SSVCDecisionEngine().compute(asset, vuln)

    assert result["ssvc_decision"] == "defer"
    assert "fix on next system upgrade" in result["reasoning"]


@pytest.mark.parametrize("automatable_value", ["no", "anything-else", ""])
def test_automatable_non_yes_string_treated_as_false(automatable_value, make_asset, make_vulnerability):
    asset = make_asset(internet_facing=True)
    vuln = make_vulnerability(in_kev=True, automatable=automatable_value, technical_impact="total")

    result = SSVCDecisionEngine().compute(asset, vuln)

    assert result["automatable"] is False


def test_compute_coerces_none_exposed_and_in_kev_to_false(make_asset, make_vulnerability):
    asset = make_asset(internet_facing=None)
    vuln = make_vulnerability(in_kev=None, automatable="no", technical_impact="partial")

    result = SSVCDecisionEngine().compute(asset, vuln)

    assert result["publicly_exposed"] is False
    assert result["in_kev"] is False
    assert result["ssvc_decision"] == "defer"
