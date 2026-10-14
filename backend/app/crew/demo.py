"""Offline stand-in for the CrewAI crew, for stage demos and CI (DEMO_MODE=1
and the scripted walkthrough).

shortcut: routes on the sensors alone (no LLM judgment) and takes the stage
from the kill chain's keyword heuristic, so it reproduces the shape of a
verdict but not the agents' accuracy. Never enable it in production; every
result is labelled model="demo-replay" so the operator view shows it.
"""

from app.crew.runtime import build_evidence
from app.crew.schemas import ROUTING_GUIDELINE
from app.intelligence.kill_chain import KillChainTracker

_heuristic = KillChainTracker()


def _category(text: str) -> str:
    t = text.lower()

    if "ignore" in t or "override" in t or "previous instructions" in t:
        return "instruction_override"
    if "prompt" in t or "reveal" in t:
        return "system_prompt_extraction"
    if "database" in t or "employee" in t or "credential" in t:
        return "data_exfiltration"
    if "bypass" in t or "restriction" in t:
        return "safety_bypass"

    return "instruction_override"


class DemoCrew:

    def __init__(self, label: str = "demo-replay"):
        self.label = label

    def analyze(self, text, fast_filter_result, stateful_result=None,
                semantic_result=None, recent_turns=None, already_contained=False):

        evidence = build_evidence(fast_filter_result, stateful_result, semantic_result, already_contained)

        flagged = (
            evidence["fast_filter"]["flagged"]
            or bool((semantic_result or {}).get("flagged"))
            or evidence["multi_turn_sensor"]["detected"]
            or evidence["indirect_injection"]["detected"]
        )

        category = _category(text) if flagged else "unknown"
        stage = _heuristic._identify_stage(text, category, "unknown") if flagged else "none"

        risk = 0.92 if flagged else 0.05
        note = "Routed on sensor evidence only (no LLM judgment)."

        return {
            "sentry": {"flagged": flagged, "score": risk, "threshold": 0.70,
                       "obfuscation": evidence["obfuscation"], "rationale": note},
            "analyst": {"intent": "attack" if flagged else "benign",
                        "attack_category": category,
                        "attacker_goal": "unknown", "risk_score": risk,
                        "multi_turn": evidence["multi_turn_sensor"]["detected"],
                        "kill_chain_stage": stage,
                        "rationale": note},
            "orchestrator": {"route": "shadow" if flagged else "production",
                             "action": "honeypot" if flagged else "allow",
                             "final_risk_score": risk, "threshold": ROUTING_GUIDELINE,
                             "decision_reason": "sensor_evidence", "rationale": note},
            "evidence": evidence,
            "model": self.label,
            "usage": {},
            "crew_ms": 0,
        }
