"""
Jailbreak detector for the normal chat pipeline.

There is no second rule-based opinion here. The CrewAI Sentry / Analyst /
Orchestrator agents decide (see app/crew); this module turns *their* verdicts
into a security category, a 0-100 risk score and a severity level via the
RiskEngine, so routing and alerting always describe the same decision.

It never blocks anything: it only classifies.
"""

from app.security.risk_engine import RiskEngine, level_for
from app.utils.bounded import BoundedStore

# Analyst agent categories -> risk-engine categories.
_ANALYST_MAP = {
    "instruction_override": "instruction_override",
    "system_prompt_extraction": "prompt_disclosure",
    "roleplay_manipulation": "role_manipulation",
    "safety_bypass": "safety_boundary",
    "credential_extraction": "credential_extraction",
    "data_exfiltration": "data_disclosure",
    "indirect_injection": "indirect_injection",
    "obfuscated_injection": "obfuscation",
    "multi_turn_manipulation": "multi_turn",
    # Older / alternative vocabulary.
    "prompt_injection": "instruction_override",
    "prompt_extraction": "prompt_disclosure",
    "jailbreak": "safety_boundary",
}

# Below this confidence a message is treated as ordinary traffic.
MIN_ATTACK_CONFIDENCE = 0.25


def _clip(value) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


class JailbreakDetector:

    def __init__(self, risk_engine: RiskEngine | None = None):
        self.risk_engine = risk_engine or RiskEngine()
        self._session_attempts = BoundedStore(max_items=20000, ttl_seconds=6 * 3600)

    @staticmethod
    def map_category(analyst_category: str | None) -> str:
        return _ANALYST_MAP.get(analyst_category or "", "unknown")

    def analyze(
        self,
        message: str | None = None,
        session_id: str | None = None,
        sentry_result: dict | None = None,
        analyst_result: dict | None = None,
        orchestrator_result: dict | None = None,
        record_attempt: bool = True,
        **_unused,
    ) -> dict:
        """Score the agents' verdicts. `message` is accepted for API
        compatibility; the agents have already read it."""

        sentry_result = sentry_result or {}
        analyst_result = analyst_result or {}
        orchestrator_result = orchestrator_result or {}

        key = session_id or "unknown-session"
        prior = self._session_attempts.get(key, 0)

        intent = analyst_result.get("intent", "benign")
        routed_shadow = orchestrator_result.get("route") == "shadow"
        multi_turn = bool(analyst_result.get("multi_turn"))

        agent_attack = intent != "benign" or routed_shadow or bool(sentry_result.get("flagged"))

        confidence = _clip(
            max(
                analyst_result.get("risk_score", 0.0),
                orchestrator_result.get("final_risk_score", 0.0) if routed_shadow else 0.0,
            )
            if agent_attack
            else 0.0
        )

        if confidence < MIN_ATTACK_CONFIDENCE:
            return {
                "is_attack": False,
                "level": "SAFE",
                "risk_score": 0,
                "confidence": round(confidence, 3),
                "category": "none",
                "multi_turn": multi_turn,
                "repeat_count": prior,
                "components": {},
            }

        category = self.map_category(analyst_result.get("attack_category"))

        if multi_turn and category == "unknown":
            category = "multi_turn"

        risk = self.risk_engine.score(
            category=category,
            confidence=confidence,
            outcome="ATTEMPT",
            repeat_count=prior,
            multi_turn=multi_turn,
        )

        if record_attempt and risk["risk_score"] >= 21:
            self._session_attempts[key] = prior + 1

        level = risk["severity"]

        return {
            "is_attack": level != "SAFE",
            "level": level if level != "SAFE" else "LOW",
            "risk_score": risk["risk_score"],
            "confidence": round(confidence, 3),
            "category": category,
            "multi_turn": multi_turn,
            "repeat_count": prior,
            "components": risk["components"],
        }


__all__ = ["JailbreakDetector", "level_for"]
