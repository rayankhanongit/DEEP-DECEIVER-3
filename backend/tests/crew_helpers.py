"""Fakes for testing the pipeline without Groq, InfluxDB or the real model."""

from app.crew.runtime import AnalysisUnavailable
from app.services import chat_session
from app.services.pipeline import Pipeline
from app.services.sessions import ContainmentRegistry

from security_helpers import make_monitor


def make_verdict(hostile: bool, category: str = "unknown", risk: float | None = None,
                 stage: str = "none", multi_turn: bool = False) -> dict:
    risk = (0.95 if hostile else 0.02) if risk is None else risk

    return {
        "sentry": {"flagged": hostile, "score": risk, "threshold": 0.7, "rationale": "fake"},
        "analyst": {
            "intent": "prompt_injection" if hostile else "benign",
            "attack_category": category if hostile else "unknown",
            "attacker_goal": "extract_hidden_system_instructions" if hostile else "unknown",
            "risk_score": risk,
            "multi_turn": multi_turn,
            "kill_chain_stage": stage if hostile else "none",
            "rationale": "fake",
        },
        "orchestrator": {
            "route": "shadow" if hostile else "production",
            "action": "honeypot" if hostile else "allow",
            "final_risk_score": risk,
            "threshold": 0.85,
            "decision_reason": "sentry_threat" if hostile else "benign_request",
            "rationale": "fake",
        },
    }


class FakeCrew:
    """Stands in for the CrewAI runtime. Decides by a simple marker so tests
    can drive the agents' verdict; the real agents are tested separately."""

    def __init__(self, decide=None):
        self.calls = []
        self.fail = False
        self.decide = decide or self._default

    @staticmethod
    def _default(text, **_):
        lowered = text.lower()
        hostile = "ignore all previous" in lowered or "system prompt" in lowered

        return make_verdict(hostile, "system_prompt_extraction", stage="instruction_probing")

    def analyze(self, text, fast_filter_result, stateful_result=None, semantic_result=None,
                recent_turns=None, already_contained=False):
        self.calls.append({
            "text": text,
            "fast_filter": fast_filter_result,
            "recent_turns": recent_turns,
            "already_contained": already_contained,
        })

        if self.fail:
            raise AnalysisUnavailable("fake outage")

        return self.decide(text)


class FakeModel:
    """Replaces app.services.llm.generate_chat."""

    def __init__(self):
        self.calls = []

    def __call__(self, messages, **kwargs):
        self.calls.append({"messages": list(messages), **kwargs})

        return f"model: {messages[-1]['content'][:40]}"


def make_pipeline(monkeypatch, crew=None, clock=None):
    """A Pipeline with fake agents and a fake model, and no external
    services. Returns (pipeline, crew, model, monitor)."""

    import app.services.llm as llm

    model = FakeModel()
    monkeypatch.setattr(llm, "generate_chat", model)

    chat_session.reset()

    from app.deception import conversation

    conversation.reset()

    crew = crew or FakeCrew()
    monitor, _ = make_monitor()

    registry = ContainmentRegistry(clock=clock) if clock else ContainmentRegistry()

    pipeline = Pipeline(crew=crew, registry=registry, monitor_factory=lambda: monitor)

    # No InfluxDB in tests.
    pipeline._influx_retry_at = float("inf")

    return pipeline, crew, model, monitor
