import logging

from fastapi import APIRouter, Depends, HTTPException

from app.database.influx import validate_time_range
from app.security.operator import require_operator

logger = logging.getLogger("deep_deceiver.soc")


router = APIRouter(
    prefix="/soc",
    tags=["SOC"],
    dependencies=[Depends(require_operator)],
)

_influxdb = None


def get_influxdb():
    """Created on first use: the backend starts without InfluxDB, and the
    SOC endpoints answer 503 until it is configured."""

    global _influxdb

    if _influxdb is None:
        try:
            from app.database.influx import InfluxDBService

            _influxdb = InfluxDBService()
        except Exception as error:
            logger.warning("InfluxDB unavailable: %s", type(error).__name__)
            raise HTTPException(status_code=503, detail="Forensic store unavailable")

    return _influxdb


def _query(time_range: str, limit: int) -> list[dict]:
    try:
        validate_time_range(time_range)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error))

    return get_influxdb().query_events(time_range=time_range, limit=limit)


@router.get("/events")
def get_events(
    time_range: str = "-24h",
    limit: int = 100
):
    """
    Retrieve forensic events for the SOC dashboard.
    """

    events = _query(time_range, limit)

    return {
        "count": len(events),
        "events": events
    }


@router.get("/stats")
def get_stats(
    time_range: str = "-24h"
):
    """
    Generate SOC summary statistics from forensic events.
    """

    events = _query(time_range, 1000)

    total_events = len(events)

    threats_detected = sum(
        1
        for event in events
        if event["intent"] == "prompt_injection"
    )

    honeypot_activations = sum(
        1
        for event in events
        if event["action"] == "honeypot"
    )

    production_requests = sum(
        1
        for event in events
        if event["response_source"] == "production"
    )

    risk_scores = [
        event["final_risk_score"]
        for event in events
        if event["final_risk_score"] is not None
    ]

    average_risk_score = (
        sum(risk_scores) / len(risk_scores)
        if risk_scores
        else 0.0
    )

    attack_categories = {}

    for event in events:

        category = event["attack_category"]

        if category is None:
            continue

        attack_categories[category] = (
            attack_categories.get(category, 0) + 1
        )

    # --------------------------------------------------
    # Kill Chain statistics
    # --------------------------------------------------

    kill_chain_stages = {}

    for event in events:

        stage = event.get(
            "kill_chain_stage"
        )

        if stage is None or stage == "unknown":
            continue

        kill_chain_stages[stage] = (
            kill_chain_stages.get(stage, 0) + 1
        )

    # --------------------------------------------------
    # MITRE ATLAS statistics
    # --------------------------------------------------

    mitre_techniques = {}

    for event in events:

        technique = event.get(
            "mitre_technique"
        )

        if technique is None:
            continue

        mitre_techniques[technique] = (
            mitre_techniques.get(
                technique,
                0
            ) + 1
        )

    return {
        "time_range": time_range,

        "total_events": total_events,

        "threats_detected": threats_detected,

        "honeypot_activations": honeypot_activations,

        "production_requests": production_requests,

        "average_risk_score": round(
            average_risk_score,
            4
        ),

        "attack_categories": attack_categories,

        "kill_chain_stages": kill_chain_stages,

        "mitre_techniques": mitre_techniques,
    }