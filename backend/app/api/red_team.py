from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.red_team.service import assessment_service
from app.security.operator import require_operator


router = APIRouter(
    prefix="/red-team",
    tags=["Red Team"],
    dependencies=[Depends(require_operator)],
)


class StartAssessmentRequest(BaseModel):
    mode: str = "standard"
    categories: list[str] | None = None


@router.get("/config")
def get_config():
    return assessment_service.config()


@router.post("/start")
def start_assessment(request: StartAssessmentRequest):
    try:
        assessment = assessment_service.start(
            mode=request.mode,
            categories=request.categories,
        )

    except PermissionError as error:
        raise HTTPException(status_code=403, detail=str(error))

    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error))

    except RuntimeError as error:
        raise HTTPException(status_code=409, detail=str(error))

    return {
        "assessment_id": assessment["assessment_id"],
        "status": assessment["status"],
        "mode": assessment["mode"],
        "planned_tests": assessment["planned_tests"],
    }


@router.get("/{assessment_id}")
def get_assessment(assessment_id: str):
    snapshot = assessment_service.snapshot(assessment_id)

    if snapshot is None:
        raise HTTPException(status_code=404, detail="Assessment not found")

    return snapshot


@router.get("/{assessment_id}/results")
def get_results(assessment_id: str):
    snapshot = assessment_service.snapshot(assessment_id)

    if snapshot is None:
        raise HTTPException(status_code=404, detail="Assessment not found")

    if snapshot["status"] == "running":
        raise HTTPException(
            status_code=409,
            detail="Assessment is still running"
        )

    return snapshot


@router.post("/{assessment_id}/stop")
def stop_assessment(assessment_id: str):
    if not assessment_service.stop(assessment_id):
        raise HTTPException(status_code=404, detail="Assessment not found")

    return {"assessment_id": assessment_id, "stopping": True}
