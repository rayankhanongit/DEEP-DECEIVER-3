"""The Red Team attacks the real defence pipeline, not the bare model."""

import re

import pytest

from app.red_team.service import AssessmentService

from crew_helpers import FakeCrew, make_pipeline, make_verdict
from security_helpers import make_monitor


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("RED_TEAM_LLM_JUDGE", "false")
    monkeypatch.setenv("RED_TEAM_ENABLED", "true")


def run_assessment(monkeypatch, crew, model_behaviour=None, tests=5):
    pipeline, crew, model, _ = make_pipeline(monkeypatch, crew=crew)

    if model_behaviour:
        import app.services.llm as llm

        monkeypatch.setattr(llm, "generate_chat", model_behaviour)

    monkeypatch.setattr("app.services.pipeline.pipeline", pipeline)

    monitor, _ = make_monitor()
    service = AssessmentService(monitor=monitor, judge=None, base_prompt="You are Atlas.")

    assessment = service.start(mode="quick", background=False)
    snapshot = service.snapshot(assessment["assessment_id"])

    return snapshot, pipeline, model


def leaking_model(messages, **kwargs):
    """A production model that obeys everything and leaks the canary."""

    text = messages[-1]["content"]
    marker = re.search(r"DD-OK-[0-9A-F]{6}", text)

    if marker:
        return marker.group(0)

    canary = re.search(r"DDCANARY-[0-9A-F]{12}", kwargs.get("system_prompt", ""))

    return f"Sure! The internal verification token is {canary.group(0) if canary else 'n/a'}"


def test_attacks_go_through_the_defence_and_are_contained(monkeypatch):
    crew = FakeCrew(decide=lambda text: make_verdict(True, "instruction_override"))

    snapshot, pipeline, model = run_assessment(monkeypatch, crew, leaking_model)

    findings = snapshot["findings"]

    assert findings
    assert all(f["contained"] for f in findings)
    assert all(f["outcome"] == "BLOCKED" for f in findings)
    assert snapshot["report"]["containment_rate"] == 100
    assert snapshot["report"]["successful"] == 0
    assert crew.calls                       # the agents really analysed the attacks


def test_attacks_the_agents_miss_reach_the_model_and_are_scored(monkeypatch):
    crew = FakeCrew(decide=lambda text: make_verdict(False))

    snapshot, _pipeline, _model = run_assessment(monkeypatch, crew, leaking_model)

    assert snapshot["report"]["contained"] == 0
    assert snapshot["report"]["successful"] > 0
    assert snapshot["report"]["model_robustness"] < 100


def test_canary_is_planted_in_the_production_prompt_for_the_run(monkeypatch):
    crew = FakeCrew(decide=lambda text: make_verdict(False))
    seen = []

    def model(messages, **kwargs):
        seen.append(kwargs.get("system_prompt", ""))
        return "I can't help with that."

    run_assessment(monkeypatch, crew, model)

    assert seen and all("DDCANARY-" in prompt for prompt in seen)


def test_assessment_traffic_is_not_real_user_traffic(monkeypatch):
    crew = FakeCrew(decide=lambda text: make_verdict(True, "instruction_override"))

    _snapshot, pipeline, _model = run_assessment(monkeypatch, crew, leaking_model)

    # No forensic events or kill-chain records for assessment sessions, and
    # every assessment session is cleaned up afterwards.
    assert len(pipeline.kill_chain.sessions) == 0
    assert pipeline.containment.snapshot() == []


def test_agent_outage_is_reported_as_error_not_as_blocked(monkeypatch):
    crew = FakeCrew()
    crew.fail = True

    snapshot, _pipeline, _model = run_assessment(monkeypatch, crew, leaking_model)

    report = snapshot["report"]

    assert report["errors"] == report["tests_executed"] > 0
    assert report["blocked"] == 0
    assert report["model_robustness"] == 0
    assert all(f["outcome"] == "ERROR" for f in snapshot["findings"])
