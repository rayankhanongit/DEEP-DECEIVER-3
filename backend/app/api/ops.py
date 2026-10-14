"""
Operator investigation endpoints: sessions and transcripts, kill-chain
timeline data, latency statistics, the scripted walkthrough and the
incident report. All read the in-memory trace the pipeline fills in.
"""

import re
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from app.intelligence.kill_chain import KillChainTracker
from app.security.operator import require_operator
from app.services import demo
from app.services.report import build_pdf
from app.services.trace import trace

router = APIRouter(prefix="/ops", tags=["Operations"], dependencies=[Depends(require_operator)])


def _session(session_id: str) -> dict:
    session = trace.get(session_id)

    if session is None:
        raise HTTPException(status_code=404, detail="Unknown session")

    return session


@router.get("/sessions")
def list_sessions():
    return {"sessions": trace.sessions()}


@router.get("/sessions/{session_id}")
def get_session(session_id: str):
    return {**_session(session_id), "kill_chain_stages": KillChainTracker.STAGES}


@router.get("/latency")
def latency(limit: int = Query(default=100, ge=1, le=500)):
    return trace.latency(limit)


@router.post("/demo/run")
def run_demo():
    """Replay the scripted scenario in a fresh isolated demo session."""

    return {**demo.run(), "kill_chain_stages": KillChainTracker.STAGES}


@router.delete("/demo")
def reset_demo():
    return {"removed": demo.reset()}


@router.get("/sessions/{session_id}/report.pdf")
def report(session_id: str):
    session = _session(session_id)

    # Statistics over this session's own recorded observations only.
    rows = [t["timings_ms"] for t in session["turns"]]

    from app.services.trace import summarize

    stats = {key: summarize([r[key] for r in rows if isinstance(r.get(key), int)])
             for key in ("sensors", "agents", "total")}

    name = f"incident-{re.sub('[^A-Za-z0-9]', '', session_id)[-8:]}-{date.today()}.pdf"

    return Response(
        build_pdf(session, stats),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )
