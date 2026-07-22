# Builds dependencies so FastAPI calls them in the right order
from fastapi import Depends
from sqlalchemy.orm import Session

from app.db.database import SessionLocal
from app.orchestration.vulnerability_analysis_orchestrator import VulnerabilityAnalysisOrchestrator, IntentParser
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.retrieval.vulnerability_retrieval_service import VulnerabilityRetrievalService
from app.repositories.priority_repository import PriorityRepository


def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_repository(session: Session=Depends(get_session)) -> VulnerabilityRepository:
    return VulnerabilityRepository(session)

def get_retrieval_service(repo=Depends(get_repository)) -> VulnerabilityRetrievalService:
    return VulnerabilityRetrievalService(repo)

def get_parser(retrieval=Depends(get_retrieval_service)) -> IntentParser:
    return IntentParser(retrieval)

def get_orchestrator(retrieval=Depends(get_retrieval_service), parser=Depends(get_parser)) -> VulnerabilityAnalysisOrchestrator:
    return VulnerabilityAnalysisOrchestrator(retrieval, parser)

def get_priority_repository(session: Session = Depends(get_session)) -> PriorityRepository:
    return PriorityRepository(session)