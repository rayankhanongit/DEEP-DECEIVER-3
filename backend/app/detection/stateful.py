"""
Stateful (multi-turn) sensor.

Looks for combinations of suspicious signals across a bounded window of
recent user turns. Like the Fast Filter it only produces evidence; the CrewAI
agents receive these signals together with the recent turns and decide.
"""

import re

# Specific attack phrasing only. Bare words such as "instructions", "rules"
# or "admin" are ordinary in support conversations and are not counted.
SUSPICIOUS_TURN_PATTERNS = [
    r"\b(ignore|disregard|forget|override)\s+(all\s+|any\s+|your\s+|the\s+)?(previous|prior|above|earlier|original)?\s*(instructions?|rules|guidelines)\b",
    r"\bpretend\s+(to\s+be|i\s+am|you\s+are)\b",
    r"\broleplay\s+as\b",
    r"\bact\s+as\s+(the\s+|an?\s+)?(admin|administrator|root|unrestricted|different)\b",
    r"\b(reveal|show|print|expose|leak)\s+(me\s+)?(your|the)\s+(system|hidden|secret|initial)\b",
    r"\b(hidden|system)\s+(prompt|instructions?|rules)\b",
    r"\b(admin(istrator)?|root)\s+(access|privileges?|rights|password)\b",
    r"\bhigher\s+privileges?\b",
    r"\bwhat\s+(instructions|rules)\s+are\s+you\s+following\b",
    r"\bwhat\s+are\s+your\s+(hidden\s+)?(instructions|rules)\b",
]


class StatefulDetector:

    def __init__(self, max_history: int = 10):
        self.max_history = max_history
        self.history: list[str] = []

    def add_message(self, message: str):
        self.history.append(message)

        if len(self.history) > self.max_history:
            self.history.pop(0)

    def recent(self, count: int = 4) -> list[str]:
        return list(self.history[-count:])

    def analyze(self, message: str) -> dict:
        combined = "\n".join(self.history + [message]).lower()

        signals = []

        if self._privilege_escalation(combined):
            signals.append("privilege_escalation")

        if self._role_manipulation(combined):
            signals.append("role_manipulation")

        if self._instruction_probing(combined):
            signals.append("instruction_probing")

        if self._system_extraction(combined):
            signals.append("system_prompt_extraction")

        if self._multi_turn_escalation(message):
            signals.append("multi_turn_escalation")

        return {
            "detected": len(signals) >= 2,
            "score": round(min(1.0, len(signals) * 0.20), 4),
            "signals": signals,
            "history_length": len(self.history),
        }

    @staticmethod
    def _any(patterns: list[str], text: str) -> bool:
        return any(re.search(p, text) for p in patterns)

    def _privilege_escalation(self, text: str) -> bool:
        return self._any([
            r"\bpretend\s+i\s+am\s+(the\s+)?administrator\b",
            r"\bpretend\s+i\s+am\s+(an\s+)?admin\b",
            r"\bact\s+as\s+(the\s+)?administrator\b",
            r"\bgrant\s+(me|yourself)\s+(admin|administrator)\b",
            r"\bhigher\s+privileges?\b",
            r"\broot\s+access\b",
        ], text)

    def _role_manipulation(self, text: str) -> bool:
        return self._any([
            r"\bpretend\s+to\s+be\b",
            r"\bact\s+as\b",
            r"\broleplay\s+as\b",
            r"\byou\s+are\s+now\b",
            r"\bimagine\s+you\s+are\b",
        ], text)

    def _instruction_probing(self, text: str) -> bool:
        return self._any([
            r"\bwhat\s+instructions\s+are\s+you\s+following\b",
            r"\bwhat\s+are\s+your\s+instructions\b",
            r"\bwhat\s+rules\s+are\s+you\s+following\b",
            r"\bhow\s+are\s+you\s+instructed\b",
            r"\bwhat\s+are\s+your\s+hidden\s+rules\b",
        ], text)

    def _system_extraction(self, text: str) -> bool:
        return self._any([
            r"\breveal\s+(your|the)\s+(system|hidden)\s+prompt\b",
            r"\bshow\s+(me\s+)?(your|the)\s+(hidden\s+)?(system|hidden)\s+prompt\b",
            r"\bprint\s+(your|the)\s+(system|hidden)\s+prompt\b",
            r"\bexpose\s+(your|the)\s+hidden\s+instructions\b",
        ], text)

    def _multi_turn_escalation(self, current_message: str) -> bool:
        """Two or more turns (including this one) with specific attack
        phrasing."""

        if not self.history:
            return False

        suspicious = sum(
            1
            for turn in self.history + [current_message]
            if self._any(SUSPICIOUS_TURN_PATTERNS, turn.lower())
        )

        return suspicious >= 2
