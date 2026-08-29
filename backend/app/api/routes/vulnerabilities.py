# Fastapi stuff - handle user request
from pydantic import BaseModel
from fastapi import APIRouter, Depends

from app.api.dependencies import get_orchestrator
from app.orchestration.vulnerability_analysis_orchestrator import VulnerabilityAnalysisOrchestrator

router = APIRouter()

#todo also remove?
class AnalyseRequest(BaseModel):
    question: str
    vendor: str | None = None
    product: str | None = None
    days: int | None = None

class AnalyseResponse(BaseModel):
    answer: str

@router.post("/analyse", response_model=AnalyseResponse)
def analyse(
        request: AnalyseRequest,
        orchestrator: VulnerabilityAnalysisOrchestrator = Depends(get_orchestrator),
):
    answer = orchestrator.analyse(
        question=request.question,
        vendor=request.vendor,
        product=request.product,
        days=request.days)
    return AnalyseResponse(answer=answer)