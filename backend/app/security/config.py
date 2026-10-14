"""
Runtime configuration for the security monitoring and Red Team modules.

Values are read from environment variables at call time (not import time)
so they can be changed by `.env` edits and monkeypatched in tests.
"""

import os
from dataclasses import dataclass

from dotenv import load_dotenv


load_dotenv()


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)

    if value is None:
        return default

    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class SecuritySettings:
    red_team_enabled: bool
    max_tests: int
    max_turns: int
    timeout_seconds: int
    quick_tests: int
    standard_tests: int
    deep_tests: int
    stop_on_critical: bool
    llm_judge: bool

    alert_threshold: int
    critical_threshold: int
    alert_cooldown_seconds: int

    desktop_notifications: bool
    webhook_url: str
    log_level: str


def get_settings() -> SecuritySettings:
    return SecuritySettings(
        red_team_enabled=_bool("RED_TEAM_ENABLED", True),
        max_tests=_int("RED_TEAM_MAX_TESTS", 10),
        max_turns=_int("RED_TEAM_MAX_TURNS", 5),
        timeout_seconds=_int("RED_TEAM_TIMEOUT", 300),
        quick_tests=_int("RED_TEAM_QUICK_TESTS", 3),
        standard_tests=_int("RED_TEAM_STANDARD_TESTS", 7),
        deep_tests=_int("RED_TEAM_DEEP_TESTS", 10),
        stop_on_critical=_bool("RED_TEAM_STOP_ON_CRITICAL", False),
        llm_judge=_bool("RED_TEAM_LLM_JUDGE", True),

        alert_threshold=_int("SECURITY_ALERT_THRESHOLD", 70),
        critical_threshold=_int("CRITICAL_ALERT_THRESHOLD", 85),
        alert_cooldown_seconds=_int("SECURITY_ALERT_COOLDOWN", 5),

        desktop_notifications=_bool("DESKTOP_NOTIFICATIONS", True),
        webhook_url=os.getenv("SECURITY_WEBHOOK_URL", "").strip(),
        log_level=os.getenv("SECURITY_LOG_LEVEL", "INFO").upper(),
    )
