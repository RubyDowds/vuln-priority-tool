"""
EPSS Enrichment Service parses the raw response from the EPSS FIRST API, updates the vulnerability
object with EPSS data (score and percentile)
"""
import logging

from app.repositories.vulnerability_repository import VulnerabilityRepository


class EpssEnrichmentService:
    def __init__(self, repository: VulnerabilityRepository):
        self.repository = repository
        self.logger = logging.getLogger(__name__)

    def enrich(self, epss_data: list[dict]) -> None:
        for item in epss_data:
            cve_id = item["cve"]
            if not cve_id:
                continue

            vuln = self.repository.get_by_cve_id(cve_id)
            if not vuln:
                self.logger.info(f"{cve_id} not found in local DB, skipping")
                continue

            vuln.epss_score = item["epss"]
            vuln.epss_percentile = item["percentile"]

            self.repository.save(vuln)



