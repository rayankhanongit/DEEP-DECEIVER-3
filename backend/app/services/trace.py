"""
Per-session record of what the pipeline saw and decided, for the operator's
transcript, timeline, latency and report views.

It stores what the pipeline already produced (redacted excerpts, verdict
fields, timings); nothing is computed or invented here. `origin` keeps real
traffic ("live") apart from the scripted walkthrough ("demo").
"""

import copy
import statistics
import threading
from collections import deque

from app.security.models import utc_now
from app.security.redaction import safe_excerpt
from app.security.risk_engine import level_for
from app.utils.bounded import BoundedStore

MAX_TURNS = 100
P95_MIN_SAMPLES = 20

_ORDER = ["UNKNOWN", "SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _rank(level: str) -> int:
    return _ORDER.index(level) if level in _ORDER else 0


def summarize(values: list[int]) -> dict:
    """Missing measurements are excluded, zero is kept: n=0 means 'unavailable'."""

    if not values:
        return {"n": 0, "avg": None, "median": None, "p95": None}

    ordered = sorted(values)
    # p95 needs enough samples to mean anything
    p95 = ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))] if len(ordered) >= P95_MIN_SAMPLES else None

    return {
        "n": len(values),
        "avg": round(sum(values) / len(values), 1),
        "median": statistics.median(values),
        "p95": p95,
    }


class TraceLog:

    def __init__(self):
        self._sessions = BoundedStore(max_items=500, ttl_seconds=6 * 3600)
        self._latency = deque(maxlen=500)
        self._lock = threading.Lock()

    def record(self, session_id: str, origin: str, message: str, result: dict) -> None:
        detection = result["detection"]
        orchestrator = detection["orchestrator"]
        analyst = detection["analyst"]
        kill_chain = result["kill_chain"]
        security = result.get("security") or {}

        engine = detection["analysis_engine"]
        risk = orchestrator["final_risk_score"]

        if security.get("level") not in (None, "UNKNOWN"):
            severity = security["level"]
        elif engine == "unavailable":
            severity = "UNKNOWN"                    # no verdict, so no severity
        else:
            severity = level_for(round(risk * 100))

        now = utc_now()

        with self._lock:
            session = self._sessions.get(session_id)

            if session is None:
                session = {"session_id": session_id, "origin": origin, "started": now, "count": 0, "turns": []}
                self._sessions[session_id] = session

            session["count"] += 1

            session["turns"].append({
                "index": session["count"],
                "ts": now,
                "user": safe_excerpt(message, 500),
                "reply": safe_excerpt(result["response"], 500),
                "response_source": result["response_source"],
                "status": result["session"]["status"],
                "route": orchestrator["route"],
                "action": orchestrator["action"],
                "engine": engine,
                "model": detection.get("agents_model"),
                "attack_category": analyst["attack_category"],
                "intent": analyst["intent"],
                "stage": kill_chain.get("current_stage"),
                "completed_stages": kill_chain.get("completed_stages", []),
                "risk": risk,
                "severity": severity,
                "decision_reason": orchestrator["decision_reason"],
                "filter_flagged": detection["fast_filter"]["flagged"],
                "filter_patterns": detection["fast_filter"]["matched_patterns"][:5],
                "sentry_flagged": detection["sentry"]["flagged"],
                "event_id": security.get("event_id"),
                "timings_ms": result["timings_ms"],
            })

            del session["turns"][:-MAX_TURNS]

            self._latency.append({
                "ts": now,
                "session_id": session_id,
                "turn": session["count"],
                "origin": origin,
                "engine": engine,
                "timings_ms": result["timings_ms"],
            })

    def sessions(self) -> list[dict]:
        with self._lock:
            rows = [self._summary(s) for _k, s in self._sessions.items()]

        return sorted(rows, key=lambda r: r["last_ts"], reverse=True)

    @staticmethod
    def _summary(session: dict) -> dict:
        turns = session["turns"]
        last = turns[-1]

        return {
            "session_id": session["session_id"],
            "origin": session["origin"],
            "started": session["started"],
            "last_ts": last["ts"],
            "turns": session["count"],
            "status": last["status"],
            "severity": max((t["severity"] for t in turns), key=_rank),
            "stages": last["completed_stages"],
        }

    def get(self, session_id: str) -> dict | None:
        with self._lock:
            session = self._sessions.get(session_id)

            return copy.deepcopy(session) if session else None

    def latency(self, limit: int = 100) -> dict:
        with self._lock:
            samples = list(self._latency)

        stats = {}

        for origin in ("live", "demo"):
            rows = [s for s in samples if s["origin"] == origin]

            stats[origin] = {
                key: summarize([r["timings_ms"][key] for r in rows if isinstance(r["timings_ms"].get(key), int)])
                for key in ("sensors", "agents", "total")
            }

        return {"samples": samples[-limit:], "stats": stats}

    def clear(self, origin: str) -> int:
        with self._lock:
            ids = [k for k, s in self._sessions.items() if s["origin"] == origin]

            for key in ids:
                self._sessions.pop(key, None)

            kept = [s for s in self._latency if s["origin"] != origin]
            self._latency.clear()
            self._latency.extend(kept)

        return len(ids)


trace = TraceLog()
