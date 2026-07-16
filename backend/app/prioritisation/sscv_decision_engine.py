"""
Decision engine behind determining the vulnerability prioritisation. Takes a Vulnerability and an Asset
together and computes the SSVC decision.
"""
from models.db.vulnerability import Vulnerability
from models.db.asset import Asset


class SSVCDecisionEngine:
    IMMEDIATE = {
        "outcome": "immediate",
        "days": 3,
        "reasoning": "Asset is internet-facing, CVE is in KEV, exploitation is automatable and grants "
                                 "total control"
    }
    OUT_OF_CYCLE = {
        "outcome": "out-of-cycle",
        "days": 14,
        "reasoning": "Asset is internet-facing with active exploitation or automatable attack"
    }
    SCHEDULED = {
        "outcome": "scheduled",
        "days": 60,
        "reasoning": "CVE is in KEV or asset is exposed with significant impact"
    }
    DEFER = {
        "outcome": "defer",
        "days": None,
        "reasoning": "Low exploitation risk, defer to next upgrade cycle"
    }

    def compute(self, asset: Asset, vuln: Vulnerability) -> dict:
        exposed = asset.internet_facing
        in_kev = vuln.in_kev
        automatable = vuln.automatable == "yes" # convert string values in DB to boolean for decision logic
        total_control = vuln.technical_impact == "total"

        decision = self._decide(exposed, in_kev, automatable, total_control)

        return {
            "asset_id": asset.asset_id,
            "cve_id": vuln.cve_id,
            "ssvc_decision": decision["outcome"],
            "remediation_days": decision["days"],
            "publicly_exposed": exposed,
            "in_kev": in_kev,
            "automatable": automatable,
            "technical_impact": vuln.technical_impact,
            "reasoning": decision["reasoning"]
        }

    @staticmethod
    def _decide(exposed, in_kev, automatable, total_control) -> dict:
        if exposed and in_kev and automatable and total_control:
            return SSVCDecisionEngine.IMMEDIATE
        elif exposed and (in_kev or automatable):
            return SSVCDecisionEngine.OUT_OF_CYCLE
        elif in_kev or (exposed and total_control):
            return SSVCDecisionEngine.SCHEDULED
        else:
            return SSVCDecisionEngine.DEFER


