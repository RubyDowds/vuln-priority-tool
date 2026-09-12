"""
Orchestrator to run the prioritisation once. Gets all AssetVulnerability pairs from the DB, for each pair,
fetches Asset and Vulnerability objects, before passing them to the SSVC Decision Engine and persisting the
results via the PriorityRepository. This is the write path.
"""
from app.prioritisation.ssvc_decision_engine import SSVCDecisionEngine
from app.repositories.asset_repository import AssetRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.repositories.priority_repository import PriorityRepository


class PrioritisationOrchestrator:
    def __init__(self,
                 asset_repository: AssetRepository,
                 vuln_repository: VulnerabilityRepository,
                 decision_engine: SSVCDecisionEngine,
                 priority_repository: PriorityRepository):
        self.asset_repository = asset_repository
        self.vuln_repository = vuln_repository
        self.decision_engine = decision_engine
        self.priority_repository = priority_repository


    def run_prioritisation(self):
        asset_vulns = self.asset_repository.get_all_asset_vulnerabilities()

        for av in asset_vulns:
            asset = self.asset_repository.get_by_id(av.asset_id)
            vuln = self.vuln_repository.get_by_cve_id(av.cve_id)

            if not asset or not vuln:
                continue

            priority = self.decision_engine.compute(asset, vuln)
            print(priority)
            self.priority_repository.upsert(priority)
