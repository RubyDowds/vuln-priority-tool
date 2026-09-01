# Fastapi stuff - handle user request
from pydantic import BaseModel
from fastapi import APIRouter, Depends

from app.api.dependencies import get_orchestrator
from app.orchestration.priority_analysis_orchestrator import PriorityAnalysisOrchestrator

router = APIRouter()

#todo also remove?
class AnalyseRequest(BaseModel):
    question: str
    vendor: str | None = None
    product: str | None = None
    days: int | None = None

class AnalyseResponse(BaseModel):
    answer: str

#todo not sure what im using this for
@router.post("/analyse", response_model=AnalyseResponse)
def analyse(
        request: AnalyseRequest,
        orchestrator: PriorityAnalysisOrchestrator = Depends(get_orchestrator),
):
    answer = orchestrator.analyse(
        question=request.question)
    return AnalyseResponse(answer=answer)