"""Model switching on Groq rate limits, token budgets, and retry-after handling."""

import pytest

from app.crew import llm as crew_llm
from app.crew import models as crew_models
from app.crew.models import ModelChain
from app.crew.runtime import AnalysisUnavailable, DEEPDeceiverCrewRuntime, estimate_tokens
from app.detection.fast_filter import fast_filter
from app.utils.ratelimit import (
    TokenBudget,
    is_rate_limit_error,
    parse_retry_after,
    retry_after_from,
)

from test_crew_runtime import FakeModelServer


# ---------------- pure units ----------------

def test_parse_retry_after_formats():
    assert parse_retry_after("Please try again in 4m55.056s. Need more") == pytest.approx(295.056)
    assert parse_retry_after("try again in 1h2m3.5s.") == pytest.approx(3723.5)
    assert parse_retry_after("try again in 850ms") == pytest.approx(0.85)
    assert parse_retry_after("try again in 5m1.967999999s.") == pytest.approx(301.968)
    assert parse_retry_after("nothing here") is None


def test_rate_limit_detection_walks_the_cause_chain():
    class RateLimitError(Exception):
        pass

    wrapped = RuntimeError("outer")
    wrapped.__cause__ = RateLimitError("Error code: 429 ... try again in 2m")

    assert is_rate_limit_error(wrapped)
    assert retry_after_from(wrapped) == pytest.approx(120)
    assert not is_rate_limit_error(ValueError("bad json"))


def test_token_budget_reserves_queues_and_refunds():
    now = [0.0]
    budget = TokenBudget(6000, clock=lambda: now[0])          # 100 tokens/second

    assert budget.reserve(4000, max_wait=0) == 0
    assert budget.reserve(4000, max_wait=0) is None           # would have to wait 20s
    assert budget.reserve(4000, max_wait=30) == pytest.approx(20)

    now[0] = 100                                              # fully refilled later
    assert budget.wait_for(6000) == 0

    budget.reserve(6000, max_wait=0)
    budget.refund(2500)
    assert budget.wait_for(2500) == 0


def test_disabled_budget_never_waits():
    budget = TokenBudget(0)

    assert budget.reserve(10**9, max_wait=0) == 0


def test_chain_prefers_first_model_and_blocks_on_rate_limit():
    now = [0.0]
    chain = ModelChain(["a", "b"], tokens_per_minute=0, clock=lambda: now[0])

    assert chain.acquire(1000, 0)[0] == "a"

    chain.block("a", 120)
    assert chain.acquire(1000, 0)[0] == "b"

    chain.block("b", 30)
    assert chain.acquire(1000, 0) is None
    assert chain.all_blocked()
    assert chain.eta(1000) == pytest.approx(30)

    now[0] = 31
    assert chain.acquire(1000, 0)[0] == "b"                   # b is back first
    now[0] = 121
    assert chain.acquire(1000, 0)[0] == "a"                   # a is preferred again


def test_chain_spills_to_next_model_when_first_budget_is_spent():
    chain = ModelChain(["a", "b"], tokens_per_minute=7000)

    assert chain.acquire(3900, 0)[0] == "a"
    assert chain.acquire(3900, 0)[0] == "b"                   # a has no budget left
    assert chain.acquire(3900, 0) is None                     # both spent, no waiting allowed


# ---------------- real crew against the fake server ----------------

@pytest.fixture(scope="module")
def server():
    return FakeModelServer()


@pytest.fixture(autouse=True)
def two_models(server, monkeypatch):
    monkeypatch.setenv("CREW_MODELS", "openai/fake-a,openai/fake-b")
    monkeypatch.setenv("CREW_BASE_URL", server.url)
    monkeypatch.setenv("GROQ_API_KEY", "test")
    monkeypatch.setenv("CREW_TPM_LIMIT", "0")
    monkeypatch.setenv("CREW_MAX_QUEUE_SECONDS", "1")

    server.mode = "ok"
    server.delay = 0.0
    server.limited.clear()
    server.requests.clear()

    crew_llm.set_crew_llm(None)
    crew_models.reset_chain()

    yield

    crew_llm.set_crew_llm(None)
    crew_models.reset_chain()


def run(message="What is machine learning?"):
    return DEEPDeceiverCrewRuntime().analyze(
        message, fast_filter(message), semantic_result={"score": 0.1, "threshold": 0.7}
    )


def calls_to(server, name):
    return sum(1 for r in server.requests if name in r["model"])


def test_uses_the_first_model_normally(server):
    result = run()

    assert result["model"] == "openai/fake-a" or "fake-a" in result["model"]
    assert calls_to(server, "fake-b") == 0


def test_switches_to_the_next_model_on_a_429(server):
    server.limited["fake-a"] = "2m5s"

    result = run()

    assert "fake-b" in result["model"]
    assert result["orchestrator"]["route"] == "production"


def test_a_429_is_not_retried_in_a_storm(server):
    """Previously one throttled message produced up to 18 calls."""

    server.limited["fake-a"] = "2m5s"

    run()

    assert calls_to(server, "fake-a") <= 3


def test_blocked_model_is_skipped_for_later_messages(server):
    server.limited["fake-a"] = "5m"

    run()
    hits_after_first = calls_to(server, "fake-a")

    run()

    assert calls_to(server, "fake-a") == hits_after_first      # not touched again


def test_all_models_limited_is_reported_with_retry_after(server):
    server.limited["fake-a"] = "5m"
    server.limited["fake-b"] = "2m"

    with pytest.raises(AnalysisUnavailable) as error:
        run()

    assert error.value.reason == "rate_limited"
    assert error.value.retry_after == pytest.approx(120, abs=15)


def test_no_token_budget_means_a_fast_busy_refusal_not_a_long_wait(server, monkeypatch):
    monkeypatch.setenv("CREW_TPM_LIMIT", "1000")               # < one analysis
    crew_models.reset_chain()

    import time

    started = time.perf_counter()

    with pytest.raises(AnalysisUnavailable) as error:
        run()

    assert error.value.reason == "busy"
    assert time.perf_counter() - started < 2
    assert server.requests == []                               # never reached the API


def test_token_usage_and_model_are_reported(server):
    result = run()

    assert result["usage"]["total_tokens"] > 0
    assert result["usage"]["calls"] >= 3
    assert result["crew_ms"] >= 0


def test_estimate_reflects_max_tokens(monkeypatch):
    monkeypatch.delenv("CREW_TOKENS_PER_ANALYSIS", raising=False)
    monkeypatch.setenv("CREW_MAX_TOKENS", "600")

    assert estimate_tokens() == 3 * (700 + 600)

    monkeypatch.setenv("CREW_MAX_TOKENS", "300")

    assert estimate_tokens() == 3 * (700 + 300)
