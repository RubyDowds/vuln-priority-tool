# Builds dependencies so FastAPI calls them in the right order
from fastapi import Depends
from sqlalchemy.orm import Session

from app.db.database import SessionLocal
from app.orchestration.agent_loop import AgentLoop
from app.orchestration.tools import Tools
from app.orchestration.priority_analysis_orchestrator import PriorityAnalysisOrchestrator
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.retrieval.priority_retrieval_service import PriorityRetrievalService
from app.repositories.priority_repository import PriorityRepository
from app.embeddings.priority_embedding_service import PriorityEmbeddingService


def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# def get_priority_embedding_service(repo=Depends(get_repository)) -> PriorityEmbeddingService:
#     return PriorityEmbeddingService(repo)

def get_priority_repository(session: Session = Depends(get_session)) -> PriorityRepository:
    return PriorityRepository(session)

def get_vuln_repository(session: Session=Depends(get_session)) -> VulnerabilityRepository:
    return VulnerabilityRepository(session)

def get_priority_retrieval_service(repo=Depends(get_priority_repository)) -> PriorityRetrievalService:
    return PriorityRetrievalService(repo)

def get_orchestrator(priority_repository=Depends(get_priority_repository),
                     priority_retrieval_service=Depends(get_priority_retrieval_service)) -> PriorityAnalysisOrchestrator:
    return PriorityAnalysisOrchestrator(priority_repository, priority_retrieval_service)

def get_tools(
    priority_repo=Depends(get_priority_repository),
    vulnerability_repo=Depends(get_vuln_repository),
    retrieval_service=Depends(get_priority_retrieval_service),
) -> Tools:
    return Tools(priority_repo, retrieval_service, vulnerability_repo)

def get_agent_loop(tools: Tools = Depends(get_tools)) -> AgentLoop:
    return AgentLoop(tools)