from app.embeddings.priority_embedding_service import PriorityEmbeddingService
from app.orchestration.vulnerability_analysis_orchestrator import VulnerabilityAnalysisOrchestrator
from app.repositories.priority_repository import PriorityRepository
from app.db.database import SessionLocal
from sqlalchemy.orm import Session

def build_orchestrator() -> tuple[VulnerabilityAnalysisOrchestrator, Session]:
    db = SessionLocal()
    repository = PriorityRepository(db)
    priority_embedding = PriorityEmbeddingService(repository)
    vuln_analysis = VulnerabilityAnalysisOrchestrator(priority_embedding)

    return vuln_analysis, db