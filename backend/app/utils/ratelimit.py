"""Token-per-minute budgeting and parsing of Groq's retry hints."""

import re
import threading
import time


class TokenBudget:
    """A reservation-style token bucket for one model.

    `reserve()` commits tokens immediately (the level may go negative, which
    queues later callers behind earlier ones) and tells the caller how long to
    wait before using them. A limit of 0 disables the budget.
    """

    def __init__(self, tokens_per_minute: int, clock=time.monotonic):
        self.capacity = max(0, int(tokens_per_minute))
        self.rate = self.capacity / 60.0
        self._clock = clock
        self._level = float(self.capacity)
        self._stamp = clock()
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.capacity > 0

    def _refill(self) -> None:
        now = self._clock()
        self._level = min(self.capacity, self._level + (now - self._stamp) * self.rate)
        self._stamp = now

    def wait_for(self, tokens: float) -> float:
        """Seconds until `tokens` could be used (0 if available now)."""

        if not self.enabled:
            return 0.0

        with self._lock:
            self._refill()
            missing = tokens - self._level

            return 0.0 if missing <= 0 else missing / self.rate

    def reserve(self, tokens: float, max_wait: float) -> float | None:
        """Commit `tokens`; returns the wait in seconds, or None when the wait
        would exceed `max_wait` (nothing is committed then)."""

        if not self.enabled:
            return 0.0

        with self._lock:
            self._refill()
            missing = tokens - self._level
            wait = 0.0 if missing <= 0 else missing / self.rate

            if wait > max_wait:
                return None

            self._level -= tokens

            return wait

    def refund(self, tokens: float) -> None:
        if not self.enabled or tokens <= 0:
            return

        with self._lock:
            self._refill()
            self._level = min(self.capacity, self._level + tokens)


_UNIT_SECONDS = {"h": 3600.0, "m": 60.0, "s": 1.0, "ms": 0.001}


def parse_retry_after(text: str) -> float | None:
    """Parse Groq's 'Please try again in 1h2m3.5s / 4m55s / 850ms'."""

    match = re.search(r"try again in ([0-9hms.]+)", str(text))

    if not match:
        return None

    parts = re.findall(r"(\d+(?:\.\d+)?)(ms|h|m|s)", match.group(1))

    if not parts:
        return None

    return sum(float(value) * _UNIT_SECONDS[unit] for value, unit in parts)


def is_rate_limit_error(error: BaseException) -> bool:
    """True for an HTTP 429 / RateLimitError anywhere in the cause chain."""

    seen = set()
    current = error

    while current is not None and id(current) not in seen:
        seen.add(id(current))

        if getattr(current, "status_code", None) == 429:
            return True

        if "ratelimit" in type(current).__name__.lower():
            return True

        current = current.__cause__ or current.__context__

    return "rate limit" in str(error).lower() or "rate_limit_exceeded" in str(error).lower()


def retry_after_from(error: BaseException, default: float = 60.0) -> float:
    """Seconds to avoid the model after this 429 (searches the cause chain)."""

    seen = set()
    current = error

    while current is not None and id(current) not in seen:
        seen.add(id(current))
        found = parse_retry_after(str(current))

        if found is not None:
            return found

        current = current.__cause__ or current.__context__

    return default
