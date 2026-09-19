import pytest

from app.prioritisation.ssvc_decision_engine import SSVCDecisionEngine


@pytest.mark.parametrize("exposed,in_kev,automatable,total_control,expected_outcome,expected_days", [
    (True,  True,  True,  True,  "immediate",    3),
    (True,  True,  True,  False, "out-of-cycle", 14),
    (True,  True,  False, True,  "out-of-cycle", 14),
    (True,  True,  False, False, "out-of-cycle", 14),
    (True,  False, True,  True,  "out-of-cycle", 14),
    (True,  False, True,  False, "out-of-cycle", 14),
    (True,  False, False, True,  "scheduled",    60),
    (True,  False, False, False, "defer",        None),
    (False, True,  True,  True,  "scheduled",    60),
    (False, True,  True,  False, "scheduled",    60),
    (False, True,  False, True,  "scheduled",    60),
    (False, True,  False, False, "scheduled",    60),
    (False, False, True,  True,  "defer",        None),
    (False, False, True,  False, "defer",        None),
    (False, False, False, True,  "defer",        None),
    (False, False, False, False, "defer",        None),
], ids=lambda v: str(v))
def test_compute_decision_truth_table(exposed, in_kev, automatable, total_control, expected_outcome, expected_days,
                                       make_asset, make_vulnerability):
    asset = make_asset(internet_facing=exposed)
    vuln = make_vulnerability(in_kev=in_kev,
                               automatable="yes" if automatable else "no",
                               technical_impact="total" if total_control else "partial")

    result = SSVCDecisionEngine().compute(asset, vuln)

    assert result["ssvc_decision"] == expected_outcome
    assert result["remediation_days"] == expected_days


def test_compute_returns_full_expected_dict_shape(make_asset, make_vulnerability):
    asset = make_asset(asset_id="asset-42", internet_facing=True)
    vuln = make_vulnerability(cve_id="CVE-2024-9999", in_kev=True, automatable="yes", technical_impact="total")

    result = SSVCDecisionEngine().compute(asset, vuln)

    assert result == {
        "asset_id": "asset-42",
        "cve_id": "CVE-2024-9999",
        "ssvc_decision": "immediate",
        "remediation_days": 3,
        "publicly_exposed": True,
        "in_kev": True,
        "automatable": True,
        "technical_impact": "total",
        "reasoning": SSVCDecisionEngine.IMMEDIATE["reasoning"],
    }


@pytest.mark.parametrize("automatable_value", ["no", "anything-else", ""])
def test_automatable_non_yes_string_treated_as_false(automatable_value, make_asset, make_vulnerability):
    asset = make_asset(internet_facing=True)
    vuln = make_vulnerability(in_kev=True, automatable=automatable_value, technical_impact="total")

    result = SSVCDecisionEngine().compute(asset, vuln)

    assert result["automatable"] is False
