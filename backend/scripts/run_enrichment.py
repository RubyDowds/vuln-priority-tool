import os
import logging

from dotenv import load_dotenv, find_dotenv

from app.db.database import SessionLocal, Base, engine
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.clients.nvd_client import NVDClient
from app.clients.epss_client import EpssClient
from app.enrichment.epss_enrichment_service import EpssEnrichmentService
from app.enrichment.enrichment_orchestrator import EnrichmentOrchestrator
from app.enrichment.nvd_enrichment_service import NVDEnrichmentService

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

# run_enrichment.py
def main():
    load_dotenv(find_dotenv())
    Base.metadata.create_all(engine)

    session = SessionLocal()
    try:
        vuln_repo = VulnerabilityRepository(session)
        nvd_api_key = os.getenv("NVD_API_KEY")
        if not nvd_api_key:
            raise ValueError("NVD_API_KEY environment variable is required but not set.")
        nvd_client = NVDClient(api_key=nvd_api_key)
        epss_client = EpssClient()

        nvd_enrichment_service = NVDEnrichmentService(vuln_repo)
        epss_enrichment_service = EpssEnrichmentService(vuln_repo)
        orchestrator = EnrichmentOrchestrator(
            repository=vuln_repo,
            enrichment_service=nvd_enrichment_service,
            nvd_client=nvd_client,
            epss_client=epss_client,
            epss_enrichment_service=epss_enrichment_service,
        )
        orchestrator.run()
    finally:
        session.close()


if __name__ == "__main__":
    main()
