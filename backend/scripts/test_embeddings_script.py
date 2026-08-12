import sys
import os
from dotenv import load_dotenv, find_dotenv

from app.orchestration.vulnerability_analysis_orchestrator import IntentParser, VulnerabilityAnalysisOrchestrator
from app.retrieval.vulnerability_retrieval_service import VulnerabilityRetrievalService

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from app.db.database import SessionLocal, Base, engine
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.repositories.priority_repository import PriorityRepository
from app.embeddings.vulnerability_embedding_service import VulnerabilityEmbeddingService
from app.embeddings.priority_embedding_service import PriorityEmbeddingService

if __name__ == "__main__":
    load_dotenv(find_dotenv())
    Base.metadata.create_all(bind=engine)

    session = SessionLocal()

    try:
        # embed vulns
        repo = VulnerabilityRepository(session)
        vuln_embedding_service = VulnerabilityEmbeddingService(repo)
        vuln_embedding_service.embed_all_vulnerabilities()
        print("Vulnerability embeddings complete")

        # embed priorities
        priority_repository = PriorityRepository(session)
        priority_embedding_service = PriorityEmbeddingService(priority_repository)
        priority_embedding_service.embed_all_priorities()
        print("Priority embeddings complete")
    finally:
        session.close()



