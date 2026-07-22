from fastapi import APIRouter, Depends
from pydantic import BaseModel
from app.api.dependencies import get_priority_repository, get_orchestrator
from app.repositories.priority_repository import PriorityRepository

router = APIRouter(prefix="/priorities", tags=["priorities"])

# --- Response Models ---

class PriorityResponse(BaseModel):
    asset_id: str
    cve_id: str
    ssvc_decision: str
    remediation_days: int | None
    publicly_exposed: bool
    in_kev: bool
    automatable: bool
    technical_impact: str | None
    reasoning: str

    class Config:
        from_attributes = True

class AnalyseRequest(BaseModel):
    question: str
    asset_id: str | None = None

class AnalyseResponse(BaseModel):
    answer: str

# --- Endpoints ---

@router.get("/", response_model=list[PriorityResponse])
def get_all_priorities(
        repo: PriorityRepository = Depends(get_priority_repository)
):
    return repo.get_all()

@router.get("/immediate", response_model=list[PriorityResponse])
def get_immediate_priorities(
        repo: PriorityRepository = Depends(get_priority_repository)
):
    return repo.get_immediate()

@router.get("/{asset_id}", response_model=list[PriorityResponse])
def get_priorities_for_asset(
        asset_id: str,
        repo: PriorityRepository = Depends(get_priority_repository)
):
    return repo.get_by_asset(asset_id)

@router.post("/analyse", response_model=AnalyseResponse)
def analyse(
    request: AnalyseRequest,
    repo: PriorityRepository = Depends(get_priority_repository),
    orchestrator = Depends(get_orchestrator)
):
    # fetch relevant priorities as context
    if request.asset_id:
        priorities = repo.get_by_asset(request.asset_id)
    else:
        priorities = repo.get_all()

    answer = orchestrator.analyse(
        question=request.question,
        priorities=priorities
    )
    return AnalyseResponse(answer=answer)