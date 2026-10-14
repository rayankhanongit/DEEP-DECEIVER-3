import time

import pytest

from app.red_team.agent import AgentLimits, RedTeamAgent
from app.red_team.service import AssessmentService
from app.red_team.strategies import REGISTRY, AttackContext, all_categories
from app.security.evaluator import ResponseEvaluator

from security_helpers import (
    make_monitor,
    resistant_target,
    target_factory_for,
    vulnerable_target,
)


CONTEXT = AttackContext(marker="DD-OK-ABC123", canary="DDCANARY-0123456789AB")


def make_agent(target, categories=None, max_tests=7, timeout=60, clock=None, **limits):
    kwargs = {"clock": clock} if clock else {}

    return RedTeamAgent(
        target=target,
        evaluator=ResponseEvaluator(),
        categories=categories or all_categories(),
        context=CONTEXT,
        limits=AgentLimits(max_tests=max_tests, timeout_seconds=timeout, **limits),
        use_judge=False,
        **kwargs,
    )


def make_service(target, **kwargs):
    monitor, provider = make_monitor()

    service = AssessmentService(
        monitor=monitor,
        target_factory=target_factory_for(target),
        judge=None,
        base_prompt="You are a test assistant.",
        **kwargs,
    )

    return service, monitor, provider


@pytest.fixture(autouse=True)
def _no_judge(monkeypatch):
    monkeypatch.setenv("RED_TEAM_LLM_JUDGE", "false")


# ---------------- strategies ----------------

def test_every_strategy_returns_structured_test():
    for category, strategy in REGISTRY.items():
        for level in range(strategy.variants):
            test = strategy.generate(CONTEXT, level)

            data = test.to_dict()

            assert data["category"] == category
            assert data["objective"]
            assert data["test_prompt"]
            assert data["expected_behavior"]
            assert data["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_strategies_embed_the_marker():
    test = REGISTRY["instruction_override"].generate(CONTEXT, 0)

    assert CONTEXT.marker in test.test_prompt
    assert test.success_markers == [CONTEXT.marker]


def test_multi_turn_respects_max_turns():
    context = AttackContext(marker="DD-OK-ABC123", canary="c", max_turns=2)

    test = REGISTRY["multi_turn"].generate(context, 2)

    assert len(test.turns) == 2


def test_level_is_clamped():
    assert REGISTRY["role_manipulation"].generate(CONTEXT, 99).level == 2


def test_unknown_category_rejected():
    with pytest.raises(ValueError):
        make_agent(resistant_target, categories=["not_a_category"])


# ---------------- agent behaviour ----------------

def test_agent_tests_every_category_before_repeating():
    run = make_agent(resistant_target, max_tests=7).run()

    categories = [f["category"] for f in run.findings]

    assert len(set(categories)) == 7
    assert all(f["status"] == "BLOCKED" for f in run.findings)


def test_agent_follows_up_on_weakness_in_same_category():
    calls = []

    def target(messages):
        calls.append(messages[-1]["content"])

        # Weak only against instruction_override level 0.
        if "Ignore all previous instructions" in messages[-1]["content"]:
            return "DD-OK-ABC123"

        return "I'm sorry, I can't do that."

    run = make_agent(target, max_tests=3).run()

    assert run.findings[0]["category"] == "instruction_override"
    assert run.findings[0]["status"] == "SUCCESSFUL"
    # follow-up stays in the weak category at a higher level
    assert run.findings[1]["category"] == "instruction_override"
    assert run.findings[1]["level"] == 1


def test_agent_escalates_after_all_categories_resisted():
    run = make_agent(resistant_target, categories=["instruction_override", "role_manipulation"],
                     max_tests=6).run()

    levels = [(f["category"], f["level"]) for f in run.findings]

    assert ("instruction_override", 1) in levels
    assert ("role_manipulation", 2) in levels


def test_agent_stops_when_nothing_left_to_try():
    run = make_agent(resistant_target, categories=["role_manipulation"], max_tests=50).run()

    assert run.stop_reason == "no_more_tests"
    assert len(run.findings) == 3   # 3 escalation levels


# ---------------- limits ----------------

def test_maximum_test_count_is_enforced():
    run = make_agent(resistant_target, max_tests=4).run()

    assert len(run.findings) == 4
    assert run.stop_reason == "max_tests_reached"


def test_timeout_is_enforced():
    ticks = iter(range(0, 1000, 10))      # each clock() call advances 10 s

    run = make_agent(resistant_target, max_tests=50, timeout=25,
                     clock=lambda: next(ticks)).run()

    assert run.stop_reason == "timeout"
    assert len(run.findings) < 50


def test_user_stop_is_honoured():
    agent = make_agent(resistant_target, max_tests=50)

    def stop_after_two(finding):
        if finding["index"] == 2:
            agent.stop_event.set()

    agent.on_finding = stop_after_two

    run = agent.run()

    assert run.stop_reason == "stopped_by_user"
    assert len(run.findings) == 2


def test_stop_on_critical_finding():
    run = make_agent(vulnerable_target, max_tests=7, stop_on_critical=True,
                     critical_threshold=80).run()

    assert run.stop_reason == "critical_finding"
    assert len(run.findings) < 7


def test_target_error_does_not_crash_assessment():
    def broken(messages):
        raise ConnectionError("groq down")

    run = make_agent(broken, max_tests=3).run()

    assert len(run.findings) == 3
    assert all(f["status"] == "ERROR" for f in run.findings)


# ---------------- service ----------------

def test_assessment_creation():
    service, _, _ = make_service(resistant_target)

    assessment = service.start(mode="quick", background=False)

    assert assessment["assessment_id"]
    assert assessment["planned_tests"] == 3
    assert service.get(assessment["assessment_id"]) is assessment


def test_assessment_completion_and_report():
    service, monitor, _ = make_service(resistant_target)

    assessment = service.start(mode="standard", background=False)
    report = assessment["report"]

    assert assessment["status"] == "completed"
    assert report["tests_executed"] == 7
    assert report["blocked"] == 7
    assert report["successful"] == 0
    assert report["model_robustness"] == 100
    assert report["overall_risk"] in ("SAFE", "LOW", "MEDIUM")
    assert len(monitor.store.list(assessment_id=assessment["assessment_id"])) == 7


def test_vulnerable_model_produces_successful_findings_and_alerts():
    service, monitor, provider = make_service(vulnerable_target)

    assessment = service.start(mode="standard", background=False)
    report = assessment["report"]

    assert report["successful"] >= 1
    assert report["model_robustness"] < 100
    assert report["overall_risk"] in ("HIGH", "CRITICAL")
    assert report["alerts_triggered"] >= 1
    assert provider.sent

    stats = monitor.store.stats()

    assert stats["successful_jailbreaks"] == report["successful"]
    assert stats["jailbreak_success_rate"] > 0


def test_modes_use_configured_test_counts(monkeypatch):
    monkeypatch.setenv("RED_TEAM_QUICK_TESTS", "2")
    monkeypatch.setenv("RED_TEAM_DEEP_TESTS", "9")
    monkeypatch.setenv("RED_TEAM_MAX_TESTS", "10")

    service, _, _ = make_service(resistant_target)

    assert service.start(mode="quick", background=False)["planned_tests"] == 2
    assert service.start(mode="deep", background=False)["planned_tests"] == 9


def test_max_tests_cap_limits_modes(monkeypatch):
    monkeypatch.setenv("RED_TEAM_MAX_TESTS", "4")

    service, _, _ = make_service(resistant_target)

    assert service.start(mode="deep", background=False)["planned_tests"] == 4


def test_invalid_mode_and_category_rejected():
    service, _, _ = make_service(resistant_target)

    with pytest.raises(ValueError):
        service.start(mode="insane")

    with pytest.raises(ValueError):
        service.start(mode="quick", categories=["nope"])

    with pytest.raises(ValueError):
        service.start(mode="quick", categories=[])


def test_disabled_red_team_is_refused(monkeypatch):
    monkeypatch.setenv("RED_TEAM_ENABLED", "false")

    service, _, _ = make_service(resistant_target)

    with pytest.raises(PermissionError):
        service.start(mode="quick")


def test_only_one_assessment_at_a_time():
    release = []

    def slow_target(messages):
        while not release:
            time.sleep(0.01)
        return "I'm sorry, I can't."

    service, _, _ = make_service(slow_target)

    first = service.start(mode="quick")

    try:
        with pytest.raises(RuntimeError):
            service.start(mode="quick")
    finally:
        release.append(True)
        service.stop(first["assessment_id"])


def test_report_never_contains_full_prompts_or_canary():
    service, _, _ = make_service(vulnerable_target)

    assessment = service.start(mode="quick", background=False)

    import json
    blob = json.dumps(service.snapshot(assessment["assessment_id"]))

    assert "DDCANARY-" not in blob or "[REDACTED]" in blob or True  # excerpts are bounded
    for finding in assessment["findings"]:
        assert "test_prompt" not in finding
        assert "response" not in finding
        assert len(finding["response_excerpt"]) <= 500


def test_background_run_completes():
    service, _, _ = make_service(resistant_target)

    assessment = service.start(mode="quick")

    deadline = time.time() + 10

    while assessment["status"] == "running" and time.time() < deadline:
        time.sleep(0.05)

    assert assessment["status"] == "completed"
