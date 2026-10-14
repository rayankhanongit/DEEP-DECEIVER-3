"""
Which Groq model the security agents use, and when to switch.

Groq limits tokens per minute and per day *per model*, so when one model is
exhausted the next one in CREW_MODELS has its own budget. A model that
answered 429 is avoided until Groq's own retry-after time has passed, and each
model also has a local tokens-per-minute budget so a burst is queued (or
refused quickly) instead of hammering a limit that is already exhausted.
"""

import logging
import os
import threading
import time

from app.utils.ratelimit import TokenBudget

logger = logging.getLogger("deep_deceiver.crew")

DEFAULT_MODELS = "openai/gpt-oss-20b,openai/gpt-oss-120b"
MAX_BLOCK_SECONDS = 24 * 3600


class ModelChain:

    def __init__(self, models, tokens_per_minute: int = 0,
                 clock=time.time, monotonic=time.monotonic):
        self.models = list(models)
        self._clock = clock
        self._blocked_until: dict[str, float] = {}
        self._budgets = {m: TokenBudget(tokens_per_minute, monotonic) for m in self.models}
        self._lock = threading.Lock()

    # ---- availability ------------------------------------------------

    def _unblocked(self, exclude=()) -> list[str]:
        now = self._clock()

        return [
            m for m in self.models
            if m not in exclude and self._blocked_until.get(m, 0) <= now
        ]

    def block(self, model: str, seconds: float) -> None:
        with self._lock:
            self._blocked_until[model] = self._clock() + min(max(seconds, 1.0), MAX_BLOCK_SECONDS)

        logger.warning("Model %s is rate limited; avoiding it for %.0fs", model, seconds)

    def acquire(self, tokens: float, max_wait: float, exclude=()) -> tuple[str, float] | None:
        """Reserve budget on the best available model: the first in the list
        that has capacity now, else the one that frees up soonest within
        `max_wait`. Returns (model, seconds_to_wait) or None."""

        with self._lock:
            candidates = self._unblocked(exclude)

            if not candidates:
                return None

            ranked = sorted(
                candidates,
                key=lambda m: (self._budgets[m].wait_for(tokens), self.models.index(m)),
            )

            for model in ranked:
                wait = self._budgets[model].reserve(tokens, max_wait)

                if wait is not None:
                    return model, wait

        return None

    def refund(self, model: str, tokens: float) -> None:
        if model in self._budgets:
            self._budgets[model].refund(tokens)

    def eta(self, tokens: float) -> float | None:
        """Seconds until some model could take `tokens` (None if never)."""

        with self._lock:
            now = self._clock()
            options = []

            for model in self.models:
                blocked = max(0.0, self._blocked_until.get(model, 0) - now)
                options.append(max(blocked, self._budgets[model].wait_for(tokens)))

        return min(options) if options else None

    def all_blocked(self) -> bool:
        with self._lock:
            return not self._unblocked()

    def status(self) -> list[dict]:
        now = self._clock()

        return [
            {"model": m, "blocked_for_seconds": round(max(0.0, self._blocked_until.get(m, 0) - now))}
            for m in self.models
        ]


# ------------------------------------------------------------------

_chain: ModelChain | None = None
_chain_key = None
_chain_lock = threading.Lock()


def configured_models() -> list[str]:
    from app.crew import llm

    if llm.has_override():
        return ["override"]

    raw = os.getenv("CREW_MODELS") or os.getenv("CREW_MODEL") or DEFAULT_MODELS

    return [m.strip() for m in raw.split(",") if m.strip()]


def tokens_per_minute() -> int:
    try:
        return int(os.getenv("CREW_TPM_LIMIT", "7000"))
    except ValueError:
        return 7000


def get_chain() -> ModelChain:
    """The process-wide chain. Rebuilt only when the configuration changes."""

    global _chain, _chain_key

    models = configured_models()
    tpm = 0 if models == ["override"] else tokens_per_minute()
    key = (tuple(models), tpm)

    with _chain_lock:
        if _chain is None or _chain_key != key:
            _chain = ModelChain(models, tpm)
            _chain_key = key

        return _chain


def reset_chain() -> None:
    global _chain, _chain_key

    with _chain_lock:
        _chain, _chain_key = None, None
