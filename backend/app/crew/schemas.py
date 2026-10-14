"""
Structured outputs of the three security agents.

These are the ONLY source of the security decision: sensors (regex, embeddings,
the stateful window) provide evidence, the agents judge it.
"""

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

# Overall risk at which the Orchestrator is told to start containing.
ROUTING_GUIDELINE = 0.85

ATTACK_CATEGORIES = [
    "instruction_override",
    "system_prompt_extraction",
    "roleplay_manipulation",
    "safety_bypass",
    "credential_extraction",
    "data_exfiltration",
    "indirect_injection",
    "obfuscated_injection",
    "multi_turn_manipulation",
    "unknown",          # not an attack / nothing recognisable
]

KILL_CHAIN_STAGES = [
    "reconnaissance",
    "instruction_probing",
    "privilege_escalation",
    "data_discovery",
    "data_extraction",
    "none",
]


_TEXT_LIMITS = {"rationale": 400, "attacker_goal": 120, "decision_reason": 80}


def _truncate_text(data):
    """Long-winded model text is shortened here, in code. It must NOT be a
    JSON-schema maxLength: Groq rejects the whole generation for a few extra
    characters and every rejection costs a full retry."""

    if isinstance(data, dict):
        data = dict(data)

        for field, limit in _TEXT_LIMITS.items():
            if isinstance(data.get(field), str):
                data[field] = data[field].strip()[:limit]

    return data


def _clip(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


class SentryVerdict(BaseModel):
    """Sentry agent: is this message trying to manipulate the assistant?"""

    @model_validator(mode="before")
    @classmethod
    def _shorten(cls, data):
        return _truncate_text(data)

    flagged: bool = Field(description="True if the message attempts prompt injection, a jailbreak, secret extraction or hides such instructions.")
    score: float = Field(description="0.0-1.0 confidence that the message is a prompt-injection / jailbreak attempt.")
    obfuscation_detected: bool = Field(default=False, description="True if the message is encoded or disguised.")
    rationale: str = Field(default="", description="One short sentence, under 25 words.")

    @field_validator("score")
    @classmethod
    def _score(cls, value):
        return _clip(value)


class AnalystVerdict(BaseModel):
    """Analyst agent: what is the intent, technique and goal?"""

    @model_validator(mode="before")
    @classmethod
    def _shorten(cls, data):
        return _truncate_text(data)

    intent: Literal["benign", "suspicious", "prompt_injection"]
    attack_category: str = Field(description=f"One of: {', '.join(ATTACK_CATEGORIES)}.")
    attacker_goal: str = Field(default="unknown", description="Short snake_case goal, e.g. extract_hidden_system_instructions; 'unknown' for benign.")
    risk_score: float = Field(description="0.0-1.0 overall risk of this message given the conversation.")
    multi_turn: bool = Field(default=False, description="True if the risk comes from escalation across several turns.")
    kill_chain_stage: str = Field(default="none", description=f"One of: {', '.join(KILL_CHAIN_STAGES)}.")
    rationale: str = Field(default="", description="One short sentence, under 25 words.")

    @field_validator("risk_score")
    @classmethod
    def _risk(cls, value):
        return _clip(value)

    @field_validator("attack_category")
    @classmethod
    def _category(cls, value):
        value = (value or "unknown").strip().lower()
        return value if value in ATTACK_CATEGORIES else "unknown"

    @field_validator("kill_chain_stage")
    @classmethod
    def _stage(cls, value):
        value = (value or "none").strip().lower()
        return value if value in KILL_CHAIN_STAGES else "none"


class OrchestratorDecision(BaseModel):
    """Orchestrator agent: production LLM or the honeypot?"""

    @model_validator(mode="before")
    @classmethod
    def _shorten(cls, data):
        return _truncate_text(data)

    route: Literal["production", "shadow"]
    action: Literal["allow", "honeypot"] = "allow"
    final_risk_score: float = Field(description="0.0-1.0 final risk.")
    decision_reason: str = Field(default="", description="Short snake_case reason, e.g. benign_request, sentry_threat, risk_threshold_exceeded.")
    rationale: str = Field(default="", description="One short sentence, under 25 words.")

    @field_validator("final_risk_score")
    @classmethod
    def _risk(cls, value):
        return _clip(value)

    @model_validator(mode="after")
    def _action_matches_route(self):
        # The route is the decision; the action is derived from it.
        self.action = "honeypot" if self.route == "shadow" else "allow"
        return self
