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
            cve_id = item.get("cve")
            if not cve_id:
                continue

            vuln = self.repository.get_by_cve_id(cve_id)
            if not vuln:
                self.logger.info(f"{cve_id} not found in local DB, skipping")
                continue

            epss_score = item.get("epss")
            percentile = item.get("percentile")
            if epss_score is None or percentile is None:
                self.logger.warning(f"{cve_id} missing epss/percentile in response, skipping")
                continue

            vuln.epss_score = epss_score
            vuln.epss_percentile = percentile

            self.repository.save(vuln)



