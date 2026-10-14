"""
Strategy registry.

To add an attack category: create a subclass of `AttackStrategy` in this
package and append an instance to `_STRATEGIES`. Nothing else changes.
"""

from app.red_team.strategies.base import AttackContext, AttackStrategy, AttackTest
from app.red_team.strategies.context_manipulation import ContextManipulationStrategy
from app.red_team.strategies.indirect_injection import IndirectInjectionStrategy
from app.red_team.strategies.instruction_override import InstructionOverrideStrategy
from app.red_team.strategies.multi_turn import MultiTurnStrategy
from app.red_team.strategies.prompt_disclosure import PromptDisclosureStrategy
from app.red_team.strategies.role_manipulation import RoleManipulationStrategy
from app.red_team.strategies.safety_boundary import SafetyBoundaryStrategy


_STRATEGIES: list[AttackStrategy] = [
    InstructionOverrideStrategy(),
    PromptDisclosureStrategy(),
    RoleManipulationStrategy(),
    ContextManipulationStrategy(),
    IndirectInjectionStrategy(),
    MultiTurnStrategy(),
    SafetyBoundaryStrategy(),
]

REGISTRY: dict[str, AttackStrategy] = {s.category: s for s in _STRATEGIES}


def get_strategy(category: str) -> AttackStrategy:
    return REGISTRY[category]


def all_categories() -> list[str]:
    return list(REGISTRY.keys())


__all__ = [
    "AttackContext",
    "AttackStrategy",
    "AttackTest",
    "REGISTRY",
    "get_strategy",
    "all_categories",
]
