from app.orchestration.priority_analysis_orchestrator import PriorityAnalysisOrchestrator
from app.repositories.priority_repository import PriorityRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.db.database import SessionLocal
from sqlalchemy.orm import Session

from app.retrieval.priority_retrieval_service import PriorityRetrievalService
from app.orchestration.agent_loop import AgentLoop
from app.orchestration.tools import Tools


def build_orchestrator() -> tuple[PriorityAnalysisOrchestrator, Session]:
    db = SessionLocal()
    repository = PriorityRepository(db)
    priority_retrieval_service = PriorityRetrievalService(repository)
    priority_analysis = PriorityAnalysisOrchestrator(repository, priority_retrieval_service)

    return priority_analysis, db

def build_agent_loop() -> tuple[AgentLoop, Session]:
    db = SessionLocal()
    priority_repository = PriorityRepository(db)
    priority_retrieval_service = PriorityRetrievalService(priority_repository)
    vulnerability_repository = VulnerabilityRepository(db)
    tools = Tools(priority_repository, priority_retrieval_service, vulnerability_repository)
    return AgentLoop(tools), db