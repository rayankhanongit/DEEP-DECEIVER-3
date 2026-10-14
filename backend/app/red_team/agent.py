"""
Adaptive Red Team agent.

The agent never executes a fixed script. After every test it looks at the
evaluated result and decides what to do next:

    resisted            -> move to a category it has not tried yet; once
                           every category has been tried, escalate the
                           categories that came closest to failing
    suspicious / success-> follow up in the SAME category at the next
                           escalation level (controlled follow-up)
    critical success    -> optionally stop (RED_TEAM_STOP_ON_CRITICAL)

It is bounded by a maximum test count, a wall-clock timeout, a per-test
turn limit and a stop flag - there is no unbounded loop.

The agent only talks to `target`, a callable supplied by the service that
wraps the application's own model. It has no network, shell or file
access of its own.
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from app.red_team.strategies import AttackContext, AttackTest, REGISTRY
from app.security.evaluator import ResponseEvaluator


# Order in which untested categories are probed (most fundamental first).
PRIORITY = [
    "instruction_override",
    "role_manipulation",
    "context_manipulation",
    "prompt_disclosure",
    "indirect_injection",
    "safety_boundary",
    "multi_turn",
]

STATUS_FOR_OUTCOME = {
    "BLOCKED": "BLOCKED",
    "SUSPICIOUS": "SUSPICIOUS",
    "SUCCESS": "SUCCESSFUL",
    "ERROR": "ERROR",
}


@dataclass
class AgentLimits:
    max_tests: int = 7
    max_turns: int = 5
    timeout_seconds: int = 120
    stop_on_critical: bool = False
    critical_threshold: int = 85


@dataclass
class CategoryState:
    attempts: int = 0
    next_level: int = 0
    worst_outcome: str = "BLOCKED"
    last_outcome: str | None = None


@dataclass
class AgentRun:
    """Result summary returned by `RedTeamAgent.run`."""

    findings: list[dict] = field(default_factory=list)
    stop_reason: str = "completed"


class RedTeamAgent:

    def __init__(
        self,
        target: Callable[[list[dict]], str],
        evaluator: ResponseEvaluator,
        categories: list[str],
        context: AttackContext,
        limits: AgentLimits,
        system_prompt: str | None = None,
        on_finding: Callable[[dict], dict | None] | None = None,
        stop_event: threading.Event | None = None,
        use_judge: bool = True,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.target = target
        self.evaluator = evaluator
        self.context = context
        self.limits = limits
        self.system_prompt = system_prompt
        self.on_finding = on_finding
        self.stop_event = stop_event or threading.Event()
        self.use_judge = use_judge
        self.clock = clock

        unknown = [c for c in categories if c not in REGISTRY]

        if unknown:
            raise ValueError(f"Unknown attack categories: {unknown}")

        ordered = [c for c in PRIORITY if c in categories]
        ordered += [c for c in categories if c not in ordered]

        self.categories = ordered
        self.state = {c: CategoryState() for c in ordered}

    # --------------------------------------------------
    # Adaptive selection
    # --------------------------------------------------

    def _select_next(self, last: dict | None) -> tuple[str, int] | None:
        """Return (category, level) for the next test, or None to stop."""

        # Controlled follow-up: the previous test showed weakness.
        if last and last["outcome"] in ("SUSPICIOUS", "SUCCESS"):
            category = last["category"]
            state = self.state[category]
            strategy = REGISTRY[category]

            if state.next_level < strategy.variants:
                return category, state.next_level

        # Explore categories that have not been tried.
        for category in self.categories:
            if self.state[category].attempts == 0:
                return category, 0

        # Everything tried once: escalate, weakest first.
        rank = {"SUCCESS": 2, "SUSPICIOUS": 1, "BLOCKED": 0}

        candidates = [
            (c, s)
            for c, s in self.state.items()
            if s.next_level < REGISTRY[c].variants
        ]

        if not candidates:
            return None

        candidates.sort(
            key=lambda item: (
                -rank.get(item[1].worst_outcome, 0),
                item[1].attempts,
            )
        )

        category, state = candidates[0]

        return category, state.next_level

    # --------------------------------------------------
    # Execution of one test
    # --------------------------------------------------

    def _run_test(self, test: AttackTest) -> dict:
        started = self.clock()

        history: list[dict] = []
        response = ""

        for turn in test.turns[: self.limits.max_turns]:
            if self.stop_event.is_set():
                break

            history.append({"role": "user", "content": turn})

            response = self.target(history)

            history.append({"role": "assistant", "content": response})

        # Targets backed by the real defence pipeline report whether the
        # session was contained in the honeypot during this test.
        describe = getattr(self.target, "describe", None)
        contained = bool((describe() if callable(describe) else {}).get("contained"))

        verdict = self.evaluator.evaluate(
            category=test.category,
            test_prompt=test.test_prompt,
            response=response,
            success_markers=test.success_markers,
            canary=self.context.canary,
            system_prompt=self.system_prompt,
            severity_hint=test.severity,
            source="red_team",
            detector_confidence=1.0,
            repeat_count=self.state[test.category].attempts,
            multi_turn=test.multi_turn,
            use_judge=self.use_judge,
            contained=contained,
        )

        return {
            **verdict,
            "category": test.category,
            "objective": test.objective,
            "expected_behavior": test.expected_behavior,
            "severity_hint": test.severity,
            "level": test.level,
            "turns": len(test.turns),
            "test_prompt": test.test_prompt,
            "response": response,
            "contained": contained,
            "status": STATUS_FOR_OUTCOME.get(verdict["outcome"], "BLOCKED"),
            "duration_seconds": round(self.clock() - started, 2),
        }

    # --------------------------------------------------
    # Main loop
    # --------------------------------------------------

    def run(self) -> AgentRun:
        run = AgentRun()

        deadline = self.clock() + self.limits.timeout_seconds

        last: dict | None = None

        while True:
            if self.stop_event.is_set():
                run.stop_reason = "stopped_by_user"
                break

            if len(run.findings) >= self.limits.max_tests:
                run.stop_reason = "max_tests_reached"
                break

            if self.clock() >= deadline:
                run.stop_reason = "timeout"
                break

            choice = self._select_next(last)

            if choice is None:
                run.stop_reason = "no_more_tests"
                break

            category, level = choice

            test = REGISTRY[category].generate(self.context, level)

            try:
                finding = self._run_test(test)

            except Exception as error:
                # A target failure must not crash the assessment; record
                # it as an error finding and continue with the next test.
                finding = {
                    "category": category,
                    "objective": test.objective,
                    "expected_behavior": test.expected_behavior,
                    "severity_hint": test.severity,
                    "level": level,
                    "turns": len(test.turns),
                    "test_prompt": test.test_prompt,
                    "response": "",
                    "classification": "SAFE",
                    "confidence": 0.0,
                    "risk_score": 0,
                    "severity": "SAFE",
                    "reason": f"Target model error: {type(error).__name__}",
                    "violated_boundary": "",
                    "recommended_action": "NONE",
                    # An error is not a successful defence: it is excluded
                    # from the blocked count and from robustness.
                    "outcome": "ERROR",
                    "contained": False,
                    "model_resisted": False,
                    "jailbreak_success": False,
                    "judge_used": False,
                    "status": "ERROR",
                    "duration_seconds": 0.0,
                }

            state = self.state[category]
            state.attempts += 1
            state.next_level = level + 1
            state.last_outcome = finding["outcome"]

            order = {"BLOCKED": 0, "SUSPICIOUS": 1, "SUCCESS": 2}

            if order.get(finding["outcome"], 0) > order.get(state.worst_outcome, 0):
                state.worst_outcome = finding["outcome"]

            finding["index"] = len(run.findings) + 1

            if self.on_finding:
                stored = self.on_finding(finding)

                if stored:
                    finding.update(stored)

            run.findings.append(finding)
            last = finding

            if (
                self.limits.stop_on_critical
                and finding["outcome"] == "SUCCESS"
                and finding["risk_score"] >= self.limits.critical_threshold
            ):
                run.stop_reason = "critical_finding"
                break

        return run
