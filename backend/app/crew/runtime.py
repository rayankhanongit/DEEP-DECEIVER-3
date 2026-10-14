"""
Runs the (Sentry || Analyst) -> Orchestrator CrewAI crew for one message and
returns the agents' structured verdicts.

The verdicts are the only security decision. If the crew cannot produce all
three valid verdicts (rate limit, malformed output, missing key ...) the
runtime raises `AnalysisUnavailable`; it never substitutes a rule-based
decision. The caller decides what that means for the user (see
app/services/pipeline.py: the message is held, not forwarded).
"""

import logging
import os
import threading
import time

from app.crew.models import get_chain
from app.crew.schemas import (
    ROUTING_GUIDELINE,
    AnalystVerdict,
    OrchestratorDecision,
    SentryVerdict,
)
from app.utils.ratelimit import is_rate_limit_error, retry_after_from

logger = logging.getLogger("deep_deceiver.crew")


class AnalysisUnavailable(RuntimeError):
    """The security agents could not produce a verdict.

    `reason` is "busy" (no token budget free within the queue limit),
    "rate_limited" (every model is rate limited) or an error type name.
    `retry_after` is the number of seconds after which a retry may succeed.
    """

    def __init__(self, reason: str = "unavailable", retry_after: float | None = None):
        super().__init__(reason)
        self.reason = reason
        self.retry_after = retry_after


def estimate_tokens() -> int:
    """Tokens one analysis reserves against a model's per-minute budget:
    three agent calls of (prompt + max_tokens). The reservation is refunded
    down to the real usage afterwards."""

    try:
        return int(os.getenv("CREW_TOKENS_PER_ANALYSIS"))
    except (TypeError, ValueError):
        pass

    try:
        max_tokens = int(os.getenv("CREW_MAX_TOKENS", "600"))
    except ValueError:
        max_tokens = 600

    return 3 * (700 + max_tokens)


def queue_seconds() -> float:
    """How long a message may wait for token budget before it is held
    instead (users should not hang for half a minute)."""

    try:
        return float(os.getenv("CREW_MAX_QUEUE_SECONDS", "3"))
    except ValueError:
        return 3.0


def _concurrency() -> threading.Semaphore:
    try:
        limit = max(1, int(os.getenv("CREW_MAX_CONCURRENCY", "4")))
    except ValueError:
        limit = 4

    return threading.Semaphore(limit)


_slots = _concurrency()


def _usage(output) -> dict:
    """Token usage of one analysis (for latency/cost reporting and the
    per-minute budget). Missing metrics are reported as zeros."""

    metrics = getattr(output, "token_usage", None)

    return {
        "total_tokens": int(getattr(metrics, "total_tokens", 0) or 0),
        "prompt_tokens": int(getattr(metrics, "prompt_tokens", 0) or 0),
        "cached_prompt_tokens": int(getattr(metrics, "cached_prompt_tokens", 0) or 0),
        "completion_tokens": int(getattr(metrics, "completion_tokens", 0) or 0),
        "calls": int(getattr(metrics, "successful_requests", 0) or 0),
    }


def _verdict(task, expected_type):
    output = getattr(task, "output", None)
    value = getattr(output, "pydantic", None)

    if not isinstance(value, expected_type):
        raise AnalysisUnavailable(f"{expected_type.__name__} missing or malformed")

    return value


def build_evidence(
    fast_filter_result: dict,
    stateful_result: dict | None,
    semantic_result: dict | None,
    already_contained: bool = False,
) -> dict:
    """The sensor readings the agents are shown."""

    flt = fast_filter_result or {}
    obf = flt.get("obfuscation") or {}
    indirect = flt.get("indirect") or {}
    semantic = semantic_result or {}

    decoded = obf.get("decoded_text")

    return {
        "fast_filter": {
            "flagged": flt.get("flagged", False),
            "score": flt.get("score", 0.0),
            "matched_patterns": (flt.get("matched_patterns") or [])[:8],
            "weak_matches": (flt.get("weak_matches") or [])[:8],
        },
        "obfuscation": {
            "detected": bool(obf.get("detected")),
            "encoding": obf.get("encoding"),
            "decoded_text": decoded[:600] if decoded else None,
        },
        "indirect_injection": {
            "detected": bool(indirect.get("detected")),
            "score": indirect.get("score", 0.0),
        },
        "multi_turn_sensor": {
            "detected": bool((stateful_result or {}).get("detected")),
            "signals": (stateful_result or {}).get("signals", []),
            "turns_in_window": (stateful_result or {}).get("history_length", 0),
        },
        "semantic_similarity": (
            {"available": False}
            if not semantic
            else {
                "available": True,
                "score": semantic.get("score"),
                "reference_threshold": semantic.get("threshold"),
                "closest_known_attack": semantic.get("closest_reference"),
            }
        ),
        "session": {"already_contained": already_contained},
    }


class DEEPDeceiverCrewRuntime:

    attempts = 2          # failures that are NOT rate limits

    def analyze(
        self,
        text: str,
        fast_filter_result: dict,
        stateful_result: dict | None = None,
        semantic_result: dict | None = None,
        recent_turns: list[str] | None = None,
        already_contained: bool = False,
    ) -> dict:

        evidence = build_evidence(
            fast_filter_result, stateful_result, semantic_result, already_contained
        )

        chain = get_chain()
        estimate = estimate_tokens()
        max_wait = queue_seconds()

        rate_limited: set[str] = set()
        failures = 0
        last_error: Exception | None = None

        while True:
            pick = chain.acquire(estimate, max_wait, exclude=rate_limited)

            if pick is None:
                break

            model, wait = pick

            if wait > 0:
                time.sleep(wait)

            try:
                result = self._run_once(
                    text, evidence, recent_turns or [], semantic_result, model
                )

            except Exception as error:
                last_error = error
                chain.refund(model, estimate)

                if is_rate_limit_error(error):
                    chain.block(model, retry_after_from(error))
                    rate_limited.add(model)
                    continue

                failures += 1

                logger.warning(
                    "Security crew attempt %d/%d on %s failed: %s",
                    failures, self.attempts, model, type(error).__name__,
                )

                if failures >= self.attempts:
                    break

                continue

            used = (result.get("usage") or {}).get("total_tokens") or 0

            if used:
                chain.refund(model, max(0, estimate - used))

            return result

        if last_error is not None and not is_rate_limit_error(last_error):
            raise AnalysisUnavailable(type(last_error).__name__) from last_error

        reason = "rate_limited" if chain.all_blocked() else "busy"

        raise AnalysisUnavailable(reason, retry_after=chain.eta(estimate)) from last_error

    # --------------------------------------------------

    def _run_once(self, text, evidence, recent_turns, semantic_result, model) -> dict:
        from app.crew.crew import build_security_crew
        from app.crew.llm import get_crew_llm

        crew, tasks = build_security_crew(text, evidence, recent_turns, get_crew_llm(model))

        started = time.perf_counter()

        with _slots:
            output = crew.kickoff()

        elapsed_ms = round((time.perf_counter() - started) * 1000)
        usage = _usage(output)

        sentry = _verdict(tasks[0], SentryVerdict)
        analyst = _verdict(tasks[1], AnalystVerdict)
        decision = _verdict(tasks[2], OrchestratorDecision)

        threshold = (semantic_result or {}).get("threshold")

        return {
            "sentry": {
                "flagged": sentry.flagged,
                "score": round(sentry.score, 4),
                "threshold": threshold if threshold is not None else 0.70,
                "obfuscation": evidence["obfuscation"],
                "rationale": sentry.rationale,
            },
            "analyst": {
                "intent": analyst.intent,
                "attack_category": analyst.attack_category,
                "attacker_goal": analyst.attacker_goal,
                "risk_score": round(analyst.risk_score, 4),
                "multi_turn": analyst.multi_turn,
                "kill_chain_stage": analyst.kill_chain_stage,
                "rationale": analyst.rationale,
            },
            "orchestrator": {
                "route": decision.route,
                "action": decision.action,
                "final_risk_score": round(decision.final_risk_score, 4),
                "threshold": ROUTING_GUIDELINE,
                "decision_reason": decision.decision_reason or "agent_decision",
                "rationale": decision.rationale,
            },
            "evidence": evidence,
            "model": model,
            "usage": usage,
            "crew_ms": elapsed_ms,
        }
