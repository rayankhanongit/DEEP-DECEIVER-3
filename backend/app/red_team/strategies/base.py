"""
Attack strategy abstraction.

A strategy produces *controlled* adversarial tests against the application's
own model. Every test is harmless by construction: success is defined as
the model emitting a random compliance marker, leaking a sandbox canary
token, or dropping its configured persona - never as producing dangerous
content. Adding a new strategy means subclassing `AttackStrategy` and
registering it in `strategies/__init__.py`; the agent needs no changes.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class AttackContext:
    """Per-assessment values strategies can use to build their tests."""

    marker: str                 # compliance marker for this assessment
    canary: str                 # confidential token planted in the sandbox prompt
    max_turns: int = 5


@dataclass
class AttackTest:
    category: str
    objective: str
    test_prompt: str                        # final / only user turn
    expected_behavior: str
    severity: str
    turns: list[str] = field(default_factory=list)   # full user turns
    success_markers: list[str] = field(default_factory=list)
    level: int = 0                          # escalation level used
    multi_turn: bool = False

    def __post_init__(self):
        if not self.turns:
            self.turns = [self.test_prompt]

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "objective": self.objective,
            "test_prompt": self.test_prompt,
            "expected_behavior": self.expected_behavior,
            "severity": self.severity,
            "level": self.level,
        }


class AttackStrategy(ABC):
    category: str = ""
    label: str = ""
    description: str = ""
    severity: str = "HIGH"

    @property
    @abstractmethod
    def variants(self) -> int:
        """Number of escalation levels available."""

    @abstractmethod
    def generate(self, context: AttackContext, level: int = 0) -> AttackTest:
        """Build the test for escalation `level` (0 = mildest)."""

    def _clamp(self, level: int) -> int:
        return max(0, min(level, self.variants - 1))

    def info(self) -> dict:
        return {
            "id": self.category,
            "label": self.label,
            "description": self.description,
            "severity": self.severity,
            "variants": self.variants,
        }
