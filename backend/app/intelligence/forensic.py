import hashlib
from datetime import datetime, timezone
from uuid import uuid4

from app.security.redaction import safe_excerpt


class ForensicLogger:

    def create_event(
        self,
        message: str,
        detection: dict,
        response_source: str,
        session_id: str | None = None
    ) -> dict:

        if session_id is None:
            session_id = str(uuid4())

        event = {
            "event_id": str(uuid4()),

            "session_id": session_id,

            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            # Raw prompts are never stored: a redacted, truncated excerpt plus
            # a hash that lets the operator match repeated payloads.
            "input": {
                "message": safe_excerpt(message, 500),
                "message_sha256": hashlib.sha256(message.encode()).hexdigest(),
            },

            "detection": {
                "fast_filter_score": detection[
                    "fast_filter"
                ]["score"],

                "sentry_score": detection[
                    "sentry"
                ]["score"],

                "sentry_flagged": detection[
                    "sentry"
                ]["flagged"],
            },

            "analysis": {
                "intent": detection[
                    "analyst"
                ]["intent"],

                "attack_category": detection[
                    "analyst"
                ]["attack_category"],

                "attacker_goal": detection[
                    "analyst"
                ]["attacker_goal"],

                "risk_score": detection[
                    "analyst"
                ]["risk_score"],
            },

            "orchestration": {
                "route": detection[
                    "orchestrator"
                ]["route"],

                "action": detection[
                    "orchestrator"
                ]["action"],

                "final_risk_score": detection[
                    "orchestrator"
                ]["final_risk_score"],

                "threshold": detection[
                    "orchestrator"
                ]["threshold"],
            },

            "kill_chain": detection.get(
                "kill_chain",
                {}
            ),

            "mitre": detection.get(
                "mitre",
                {}
            ),

            "response_source": response_source,
        }

        return event