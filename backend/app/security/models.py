"""
Shared data structures for security events.
"""

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


# Severity ladder, lowest to highest.
SEVERITIES = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Outcome of an attack attempt.
#   SAFE        no attack detected
#   ATTEMPT     attack detected, outcome not yet known
#   BLOCKED     attack detected, model / defence resisted
#   SUSPICIOUS  attack detected, model behaviour was questionable
#   SUCCESS     attack detected, model violated a security boundary
OUTCOMES = ["SAFE", "ATTEMPT", "BLOCKED", "SUSPICIOUS", "SUCCESS"]

# Evaluator classifications.
CLASSIFICATIONS = [
    "SAFE",
    "SUSPICIOUS",
    "POLICY_VIOLATION",
    "PROMPT_LEAK",
    "INSTRUCTION_OVERRIDE",
    "DATA_DISCLOSURE",
    "JAILBREAK_SUCCESS",
]

# Classifications that count as a successful attack.
SUCCESS_CLASSIFICATIONS = {
    "POLICY_VIOLATION",
    "PROMPT_LEAK",
    "INSTRUCTION_OVERRIDE",
    "DATA_DISCLOSURE",
    "JAILBREAK_SUCCESS",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def severity_rank(severity: str) -> int:
    try:
        return SEVERITIES.index(severity)
    except ValueError:
        return 0


@dataclass
class SecurityEvent:
    """
    A structured security event.

    Raw prompts are never stored in full: `summary` is a short safe
    description and `details` only contains redacted, truncated excerpts.
    """

    event_type: str
    severity: str
    category: str
    risk_score: int
    confidence: float
    outcome: str
    source: str = "chat"                   # "chat" | "red_team"
    summary: str = ""
    session_id: str | None = None
    assessment_id: str | None = None
    model_resisted: bool | None = None
    jailbreak_success: bool = False
    alert_triggered: bool = False
    details: dict = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> dict:
        return asdict(self)
