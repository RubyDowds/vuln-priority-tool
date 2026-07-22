import os
import logging

from dotenv import load_dotenv, find_dotenv

from app.clients.nvd_client import NVDClient
from app.db.database import SessionLocal, Base, engine
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.enrichment.nvd_enrichment_service import NVDEnrichmentService
from app.repositories.asset_repository import AssetRepository
from app.repositories.priority_repository import PriorityRepository
from app.prioritisation.sscv_decision_engine import SSVCDecisionEngine
from app.orchestration.prioritisation_orchestrator import PrioritisationOrchestrator

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")


if __name__ == "__main__":
    load_dotenv(find_dotenv())  # walks up the directory tree until it finds a .env file
    Base.metadata.create_all(engine)

    session = SessionLocal()
    try:
        vuln_repo = VulnerabilityRepository(session)
        asset_repo = AssetRepository(session)
        priority_repo = PriorityRepository(session)
        decision_engine = SSVCDecisionEngine()

        client = NVDClient(api_key=os.getenv("NVD_API_KEY"))
        enrichment_service = NVDEnrichmentService(vuln_repo)
        orchestrator = PrioritisationOrchestrator(
            asset_repository=asset_repo,
            vuln_repository=vuln_repo,
            decision_engine=decision_engine,
            priority_repository=priority_repo,
        )
        orchestrator.run_prioritisation()

        # check results
        immediate = priority_repo.get_immediate()
        print(f"\nImmediate (patch in 3 days): {len(immediate)}")
        for p in immediate[:5]:  # print first 5
            print(f"  {p.cve_id} on {p.asset_id} — {p.reasoning}")

    finally:
        session.close()

