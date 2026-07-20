"""
Decides what vulnerabilities to enrich with NVD data and when,
based on the enrichment status, concerning CVSS and SSVC. Daily workflow
which also owns the retry logic of enrichment attempts.
"""
import logging
from datetime import datetime, timedelta

from app.clients.nvd_client import NVDClient
from app.enrichment.nvd_enrichment_service import NVDEnrichmentService
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.clients.epss_client import EpssClient
from app.enrichment.epss_enrichment_service import EpssEnrichmentService


class EnrichmentOrchestrator:
    RETRY_AFTER = {
        "pending": 0, # never been attempted, retry
        "not_enriched": 1, # no cvss/ssvc found, probably wasn't found in NVD so retry next day
        "cvss_only": 3, # has CVSS but no SSVC, retry after 3 days
        "ssv_only": 3, # has SSVC but no CVSS, retry after 3 days
    }

    def __init__(
            self,
            repository: VulnerabilityRepository,
            enrichment_service: NVDEnrichmentService,
            nvd_client: NVDClient,
            epss_client: EpssClient,
            epss_enrichment_service: EpssEnrichmentService,
    ):
        self.repository = repository
        self.enrichment_service = enrichment_service
        self.nvd_client = nvd_client
        self.epss_client = epss_client
        self.epss_enrichment_service = epss_enrichment_service
        self.logger = logging.getLogger(__name__)

    def run(self) -> None:
        pending = self._get_pending_enrichment()

        if not pending:
            self.logger.info("No vulnerabilities pending enrichment.")

        self.logger.info("Found {} vulnerabilities ending enrichment.".format(pending))
        cve_ids = [v.cve_id for v in pending]

        # NVD enrichment
        nvd_data = self.nvd_client.fetch_all(cve_ids)
        self.enrichment_service.enrich(nvd_data)

        # EPSS enrichment - run for all CVEs, not just pending, as they change daily
        all_cve_ids = [v.cve_id for v in self.repository.get_all()]
        epss_data = self.epss_client.fetch_all(all_cve_ids)
        self.epss_enrichment_service.enrich(epss_data)

    def _get_pending_enrichment(self):
        now = datetime.utcnow()
        results = []
        for status, days in self.RETRY_AFTER.items():
            cutoff = now - timedelta(days=days)
            vulns = self.repository.get_by_enrichment_status(
                status=status,
                attempted_before=cutoff
            )
            results.extend(vulns)

        return results




