import asyncio
import json
import queue

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.security.alerts import alert_engine
from app.security.config import get_settings
from app.security.models import SEVERITIES
from app.security.monitor import get_monitor
from app.security.notifications import notification_service
from app.security.operator import require_operator


router = APIRouter(
    prefix="/security",
    tags=["Security"],
    dependencies=[Depends(require_operator)],
)


class AnalyzeRequest(BaseModel):
    message: str = Field(min_length=1, max_length=8000)
    session_id: str | None = None


@router.post("/analyze")
def analyze(request: AnalyzeRequest):
    """
    Classify a message with the CrewAI agents and score their verdict with
    the risk engine. Read-only: no session state, nothing stored, no alert.
    """

    from app.crew.runtime import AnalysisUnavailable
    from app.services.pipeline import pipeline

    try:
        verdict = pipeline.analyze_only(request.message)

    except AnalysisUnavailable:
        raise HTTPException(status_code=503, detail="Security agents unavailable")

    detection = get_monitor().detector.analyze(
        request.message,
        session_id=request.session_id,
        sentry_result=verdict["sentry"],
        analyst_result=verdict["analyst"],
        orchestrator_result=verdict["orchestrator"],
        record_attempt=False,
    )

    detection["agents"] = {
        "sentry": verdict["sentry"],
        "analyst": verdict["analyst"],
        "orchestrator": verdict["orchestrator"],
    }

    return detection


@router.get("/sessions")
def list_contained_sessions():
    """Sessions currently held in the honeypot."""

    from app.services.pipeline import pipeline

    sessions = pipeline.containment.snapshot()

    return {"count": len(sessions), "sessions": sessions}


@router.post("/sessions/{session_id}/release")
def release_session(session_id: str):
    """Release a contained session (e.g. after a false positive)."""

    from app.services.pipeline import pipeline

    if not pipeline.containment.release(session_id):
        raise HTTPException(status_code=404, detail="Session is not contained")

    return {"released": True, "session_id": session_id}


@router.get("/events")
def get_events(
    limit: int = Query(100, ge=1, le=1000),
    min_severity: str | None = None,
    source: str | None = None,
    assessment_id: str | None = None,
):
    if min_severity and min_severity.upper() not in SEVERITIES:
        raise HTTPException(
            status_code=422,
            detail=f"min_severity must be one of {SEVERITIES}"
        )

    events = get_monitor().store.list(
        limit=limit,
        min_severity=min_severity.upper() if min_severity else None,
        source=source,
        assessment_id=assessment_id,
    )

    return {
        "count": len(events),
        "events": events
    }


@router.get("/stats")
def get_stats(source: str | None = None):
    return get_monitor().store.stats(source=source)


@router.get("/status")
def get_status():
    settings = get_settings()

    return {
        "alert_threshold": settings.alert_threshold,
        "critical_threshold": settings.critical_threshold,
        "desktop_notifications": settings.desktop_notifications,
        "providers": [p.name for p in notification_service.providers],
        "live_subscribers": alert_engine.broadcaster.subscriber_count,
    }


@router.post("/alerts/test")
def test_alert():
    """
    Fire a synthetic HIGH alert so the host notification path can be
    verified. Not stored as a security event.
    """

    from app.security.models import SecurityEvent

    event = SecurityEvent(
        event_type="TEST_ALERT",
        severity="HIGH",
        category="instruction_override",
        risk_score=87,
        confidence=0.9,
        outcome="ATTEMPT",
        summary="Test alert",
    ).to_dict()

    delivered = notification_service.send_security_alert(event)

    alert_engine.broadcaster.publish({
        "type": "security_alert",
        "event": event,
        "critical": True,
        "test": True,
    })

    return {"delivered": delivered}


@router.get("/stream")
async def stream(request: Request):
    """Server-Sent Events: pushes HIGH / CRITICAL alerts to dashboards."""

    subscriber = alert_engine.broadcaster.subscribe()

    async def generator():
        try:
            yield "retry: 3000\n\n"

            idle = 0

            while not alert_engine.broadcaster.closed:
                if await request.is_disconnected():
                    break

                try:
                    payload = subscriber.get_nowait()
                    idle = 0
                    yield f"data: {json.dumps(payload)}\n\n"

                except queue.Empty:
                    await asyncio.sleep(0.25)
                    idle += 1

                    # Keep-alive comment so proxies keep the stream open.
                    if idle >= 60:
                        idle = 0
                        yield ": keep-alive\n\n"

        finally:
            alert_engine.broadcaster.unsubscribe(subscriber)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
