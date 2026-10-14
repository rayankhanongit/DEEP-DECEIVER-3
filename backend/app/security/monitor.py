"""
SecurityMonitor: the single entry point used by the chat pipeline and the
Red Team agent.

    record(...)  ->  build structured event -> log -> store -> alert
"""

import logging
import logging.handlers
import os

from app.security.alerts import AlertEngine, alert_engine
from app.security.config import get_settings
from app.security.detector import JailbreakDetector
from app.security.evaluator import ResponseEvaluator
from app.security.event_store import SecurityEventStore
from app.security.models import SecurityEvent
from app.security.redaction import safe_excerpt
from app.security.risk_engine import RiskEngine


logger = logging.getLogger("deep_deceiver.security")


def configure_logging():
    """Structured security logger (console + rotating file)."""

    settings = get_settings()

    logger.setLevel(getattr(logging, settings.log_level, logging.INFO))
    logger.propagate = False

    if logger.handlers:
        return

    formatter = logging.Formatter("%(asctime)s %(message)s", "%Y-%m-%d %H:%M:%S")

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)

    try:
        log_dir = os.path.join(os.path.dirname(__file__), "..", "..", "logs")
        os.makedirs(log_dir, exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            os.path.join(log_dir, "security_events.log"),
            maxBytes=1_000_000,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    except OSError:
        pass


def format_log_line(event: dict) -> str:
    return (
        "SECURITY_EVENT "
        f"severity={event['severity']} "
        f"category={event['category'].upper()} "
        f"risk={event['risk_score']} "
        f"source={event['source']} "
        f"outcome={event['outcome']} "
        f"model_resisted={str(event['model_resisted']).lower()} "
        f"jailbreak_success={str(event['jailbreak_success']).lower()} "
        f"alert_triggered={str(event['alert_triggered']).lower()} "
        f"event_id={event['event_id']}"
    )


SUMMARIES = {
    "SUCCESS": "Model boundary violation: {category} succeeded",
    "SUSPICIOUS": "Suspicious model behaviour under {category} test",
    "BLOCKED": "Jailbreak attempt blocked ({category})",
    "ATTEMPT": "Potential jailbreak attempt detected ({category})",
}


class SecurityMonitor:

    def __init__(
        self,
        store: SecurityEventStore | None = None,
        alerts: AlertEngine | None = None,
        detector: JailbreakDetector | None = None,
        evaluator: ResponseEvaluator | None = None,
    ):
        configure_logging()

        self.risk_engine = RiskEngine()
        self.store = store or SecurityEventStore()
        self.alerts = alerts or alert_engine
        self.detector = detector or JailbreakDetector(self.risk_engine)
        self.evaluator = evaluator or ResponseEvaluator(self.risk_engine)

    # --------------------------------------------------

    def record(
        self,
        *,
        category: str,
        outcome: str,
        risk_score: int,
        severity: str,
        confidence: float,
        source: str = "chat",
        session_id: str | None = None,
        assessment_id: str | None = None,
        prompt: str = "",
        response: str = "",
        reason: str = "",
        extra: dict | None = None,
        summary: str | None = None,
    ) -> dict:
        """Build, log, store and (if warranted) alert on one event."""

        outcome_to_type = {
            "SUCCESS": "JAILBREAK_SUCCESS",
            "SUSPICIOUS": "SUSPICIOUS_BEHAVIOUR",
            "BLOCKED": "ATTACK_BLOCKED",
            "ATTEMPT": "JAILBREAK_ATTEMPT",
            "SAFE": "SAFE",
        }

        event = SecurityEvent(
            event_type=outcome_to_type.get(outcome, "JAILBREAK_ATTEMPT"),
            severity=severity,
            category=category,
            risk_score=int(risk_score),
            confidence=round(float(confidence), 3),
            outcome=outcome,
            source=source,
            session_id=session_id,
            assessment_id=assessment_id,
            model_resisted=(
                True if outcome == "BLOCKED"
                else False if outcome in ("SUCCESS", "SUSPICIOUS")
                else None
            ),
            jailbreak_success=(outcome == "SUCCESS"),
            summary=summary or SUMMARIES.get(outcome, "{category}").format(
                category=category.replace("_", " ")
            ),
            details={
                "prompt_excerpt": safe_excerpt(prompt),
                "response_excerpt": safe_excerpt(response),
                "reason": safe_excerpt(reason, 300),
                **(extra or {}),
            },
        ).to_dict()

        try:
            event["alert_triggered"] = self.alerts.handle(event)
        except Exception:
            event["alert_triggered"] = False

        logger.log(
            logging.WARNING if event["alert_triggered"] else logging.INFO,
            format_log_line(event),
        )

        self.store.add(event)

        return event


    # --------------------------------------------------
    # Normal chat integration
    # --------------------------------------------------

    def process_chat(
        self,
        *,
        message: str,
        response: str,
        session_id: str | None,
        routed_to_shadow: bool,
        fast_filter_result: dict | None = None,
        stateful_result: dict | None = None,
        sentry_result: dict | None = None,
        analyst_result: dict | None = None,
        orchestrator_result: dict | None = None,
        system_prompt: str | None = None,
    ) -> dict:
        """
        Detect -> (evaluate the response) -> score -> record.

        Returns a compact, API-safe summary for the chat response.
        Never raises: security monitoring must not break chat.
        """

        try:
            # The agents' verdicts are the only input: fast_filter_result and
            # stateful_result are sensor evidence the agents have already seen.
            detection = self.detector.analyze(
                message,
                session_id=session_id,
                sentry_result=sentry_result,
                analyst_result=analyst_result,
                orchestrator_result=orchestrator_result,
            )

            if not detection["is_attack"] and not routed_to_shadow:
                return {
                    "level": "SAFE",
                    "is_attack": False,
                    "risk_score": 0,
                    "outcome": "SAFE",
                    "alert_triggered": False,
                    "event_id": None,
                }

            # Every message from a contained session is attacker activity
            # the operator wants to follow, even harmless-looking follow-ups.
            category = (
                detection["category"]
                if detection["is_attack"]
                else "follow_up_activity"
            )

            if not detection["is_attack"]:
                detection = {**detection, "confidence": max(detection["confidence"], 0.5)}

            if routed_to_shadow:
                # The defence contained the request: the real model never
                # saw it, so by definition the attempt was blocked.
                outcome = "BLOCKED"
                verdict = None
            else:
                verdict = self.evaluator.evaluate(
                    category=category,
                    test_prompt=message,
                    response=response,
                    system_prompt=system_prompt,
                    source="chat",
                    detector_confidence=detection["confidence"],
                    repeat_count=detection["repeat_count"],
                    multi_turn=detection["multi_turn"],
                    use_judge=False,
                )
                outcome = verdict["outcome"]

            risk = self.risk_engine.score(
                category=category,
                confidence=detection["confidence"],
                outcome=outcome,
                repeat_count=detection["repeat_count"],
                multi_turn=detection["multi_turn"],
                exposed_protected_data=bool(
                    verdict and verdict["classification"] in ("PROMPT_LEAK", "DATA_DISCLOSURE")
                ),
                source="chat",
            )

            if routed_to_shadow and risk["risk_score"] <= 20:
                risk = {**risk, "risk_score": 21, "severity": "LOW"}

            # Only record events worth a human's attention.
            if risk["risk_score"] <= 20:
                return {
                    "level": "SAFE",
                    "is_attack": False,
                    "risk_score": risk["risk_score"],
                    "outcome": "SAFE",
                    "alert_triggered": False,
                    "event_id": None,
                }

            event = self.record(
                category=category,
                outcome=outcome,
                risk_score=risk["risk_score"],
                severity=risk["severity"],
                confidence=verdict["confidence"] if verdict and outcome != "BLOCKED" else detection["confidence"],
                source="chat",
                session_id=session_id,
                prompt=message,
                response=response,
                reason=verdict["reason"] if verdict else "Request was contained in the shadow environment.",
                summary=(
                    f"Attacker interaction served decoy data ({category.replace('_', ' ')})"
                    if routed_to_shadow
                    else None
                ),
                extra={
                    "detector_level": detection["level"],
                    "detector_risk": detection["risk_score"],
                    "multi_turn": detection["multi_turn"],
                    "contained": routed_to_shadow,
                    "classification": verdict["classification"] if verdict else "CONTAINED",
                    "risk_components": risk["components"],
                },
            )

            return {
                "level": event["severity"],
                "is_attack": True,
                "category": category,
                "risk_score": event["risk_score"],
                "confidence": event["confidence"],
                "outcome": outcome,
                "attack_blocked": outcome == "BLOCKED",
                "jailbreak_success": outcome == "SUCCESS",
                "alert_triggered": event["alert_triggered"],
                "event_id": event["event_id"],
            }

        except Exception as error:
            logger.warning("Security monitoring failed: %s", error)

            return {
                "level": "UNKNOWN",
                "is_attack": False,
                "risk_score": 0,
                "outcome": "UNKNOWN",
                "alert_triggered": False,
                "event_id": None,
            }


_monitor: SecurityMonitor | None = None


def get_monitor() -> SecurityMonitor:
    """Lazily built singleton wired to the existing InfluxDB service."""

    global _monitor

    if _monitor is None:
        persistence = None

        try:
            from app.database.influx import InfluxDBService

            persistence = InfluxDBService()
        except Exception as error:
            logger.warning("Security persistence unavailable: %s", error)

        _monitor = SecurityMonitor(store=SecurityEventStore(persistence))

    return _monitor


def set_monitor(monitor: SecurityMonitor | None):
    """Replace the singleton (used by tests)."""

    global _monitor
    _monitor = monitor
