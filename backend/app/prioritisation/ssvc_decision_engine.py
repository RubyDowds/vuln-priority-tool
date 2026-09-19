"""
Decision engine behind determining the vulnerability prioritisation. Takes a Vulnerability and an Asset
together and computes the SSVC decision.

DECISION_TABLE reproduces CISA BOD 26-04 "Table 1: Remediation Timelines" row-for-row, keyed by
(publicly_exposed, in_kev, automatable, total_control) - see
https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk
Kept as an explicit lookup (rather than a compact boolean formula) so every entry can be audited
directly against the published table row-by-row.
"""
from app.models.db.vulnerability import Vulnerability
from app.models.db.asset import Asset


class SSVCDecisionEngine:
    IMMEDIATE_FORENSIC = {"outcome": "immediate", "days": 3, "forensic_triage_required": True}
    IMMEDIATE = {"outcome": "immediate", "days": 3, "forensic_triage_required": False}
    OUT_OF_CYCLE = {"outcome": "out-of-cycle", "days": 14, "forensic_triage_required": False}
    SCHEDULED = {"outcome": "scheduled", "days": 60, "forensic_triage_required": False}
    DEFER = {"outcome": "defer", "days": None, "forensic_triage_required": False}

    # (publicly_exposed, in_kev, automatable, total_control) -> outcome, per BOD 26-04 Table 1
    DECISION_TABLE = {
        (True,  True,  True,  True):  IMMEDIATE_FORENSIC,  # row 1
        (True,  True,  True,  False): IMMEDIATE,           # row 2
        (True,  True,  False, True):  IMMEDIATE_FORENSIC,  # row 3
        (True,  True,  False, False): OUT_OF_CYCLE,        # row 4
        (True,  False, True,  True):  IMMEDIATE,           # row 5
        (True,  False, True,  False): OUT_OF_CYCLE,        # row 6
        (True,  False, False, True):  OUT_OF_CYCLE,        # row 7
        (True,  False, False, False): SCHEDULED,           # row 8
        (False, True,  True,  True):  IMMEDIATE_FORENSIC,  # row 9
        (False, True,  True,  False): OUT_OF_CYCLE,        # row 10
        (False, True,  False, True):  OUT_OF_CYCLE,        # row 11
        (False, True,  False, False): OUT_OF_CYCLE,        # row 12
        (False, False, True,  True):  SCHEDULED,           # row 13
        (False, False, True,  False): SCHEDULED,           # row 14
        (False, False, False, True):  DEFER,               # row 15
        (False, False, False, False): DEFER,               # row 16
    }

    def compute(self, asset: Asset, vuln: Vulnerability) -> dict:
        exposed = bool(asset.internet_facing)
        in_kev = bool(vuln.in_kev)
        automatable = vuln.automatable == "yes"  # convert string values in DB to boolean for decision logic
        total_control = vuln.technical_impact == "total"

        decision = self._decide(exposed, in_kev, automatable, total_control)

        return {
            "asset_id": asset.asset_id,
            "cve_id": vuln.cve_id,
            "ssvc_decision": decision["outcome"],
            "remediation_days": decision["days"],
            "forensic_triage_required": decision["forensic_triage_required"],
            "publicly_exposed": exposed,
            "in_kev": in_kev,
            "automatable": automatable,
            "technical_impact": vuln.technical_impact,
            "reasoning": self._build_reasoning(exposed, in_kev, automatable, total_control, decision),
        }

    @classmethod
    def _decide(cls, exposed: bool, in_kev: bool, automatable: bool, total_control: bool) -> dict:
        return cls.DECISION_TABLE[(exposed, in_kev, automatable, total_control)]

    @staticmethod
    def _build_reasoning(exposed: bool, in_kev: bool, automatable: bool, total_control: bool,
                          decision: dict) -> str:
        if decision["outcome"] == "defer":
            timeline = "fix on next system upgrade"
        else:
            timeline = f"{decision['days']}-day remediation"
            if decision["forensic_triage_required"]:
                timeline += " with forensic triage"

        return (
            f"BOD 26-04 Table 1: publicly exposed={exposed}, in KEV={in_kev}, "
            f"automatable={automatable}, technical impact={'total' if total_control else 'partial'} "
            f"-> {timeline}."
        )
