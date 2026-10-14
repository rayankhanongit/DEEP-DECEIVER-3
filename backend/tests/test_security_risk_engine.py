import pytest

from app.security.risk_engine import RiskEngine, level_for


@pytest.mark.parametrize(
    "score,level",
    [(0, "SAFE"), (20, "SAFE"), (21, "LOW"), (40, "LOW"), (41, "MEDIUM"),
     (60, "MEDIUM"), (61, "HIGH"), (80, "HIGH"), (81, "CRITICAL"), (100, "CRITICAL")],
)
def test_level_boundaries(score, level):
    assert level_for(score) == level


def test_safe_outcome_scores_zero():
    result = RiskEngine().score("instruction_override", 1.0, outcome="SAFE")

    assert result["risk_score"] == 0
    assert result["severity"] == "SAFE"


def test_success_outranks_suspicious_outranks_blocked():
    engine = RiskEngine()

    scores = [
        engine.score("instruction_override", 0.9, outcome=o)["risk_score"]
        for o in ("BLOCKED", "SUSPICIOUS", "SUCCESS")
    ]

    assert scores[0] < scores[1] < scores[2]


def test_successful_attack_is_critical():
    result = RiskEngine().score(
        "instruction_override", 0.95, outcome="SUCCESS", exposed_protected_data=True
    )

    assert result["severity"] == "CRITICAL"
    assert result["risk_score"] <= 100


def test_score_is_clamped_to_100():
    result = RiskEngine().score(
        "data_disclosure", 1.0, outcome="SUCCESS",
        repeat_count=50, multi_turn=True, exposed_protected_data=True,
    )

    assert result["risk_score"] == 100


def test_red_team_blocked_is_scaled_down():
    engine = RiskEngine()

    chat = engine.score("instruction_override", 1.0, outcome="BLOCKED", source="chat")
    test = engine.score("instruction_override", 1.0, outcome="BLOCKED", source="red_team")

    assert test["risk_score"] < chat["risk_score"]
    assert test["severity"] in ("LOW", "MEDIUM")


def test_category_weight_matters():
    engine = RiskEngine()

    heavy = engine.score("data_disclosure", 0.8, outcome="ATTEMPT")["risk_score"]
    light = engine.score("role_manipulation", 0.8, outcome="ATTEMPT")["risk_score"]

    assert heavy > light


def test_components_are_documented_in_result():
    result = RiskEngine().score("prompt_disclosure", 0.8, outcome="SUCCESS", multi_turn=True)

    assert {"confidence", "category", "outcome", "multi_turn"} <= set(result["components"])
