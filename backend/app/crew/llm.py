import logging
import os
import threading

logger = logging.getLogger("deep_deceiver.crew")

_llms: dict = {}
_override = None
_lock = threading.Lock()
_patched = False


def _limit_provider_retries() -> None:
    """Rate limits are handled by the ModelChain (switch model or hold), not by
    sleeping inside the call. Without this, one throttled message was retried
    up to 3 (CrewAI) x 3 (OpenAI SDK) x 2 (our loop) times against a limit
    that had already said no, which is where ~30 s latencies came from."""

    global _patched

    if _patched:
        return

    try:
        import crewai.llms.retry as retry

        retry._LLM_RATE_LIMIT_MAX_ATTEMPTS = 1
    except Exception as error:                      # CrewAI internals moved
        logger.warning("Could not limit CrewAI's rate-limit retries: %s", error)

    _patched = True


def has_override() -> bool:
    return _override is not None


def get_crew_llm(model: str | None = None):
    """The model behind the security agents, created on first use so the
    application can import and start without a key (analysis then reports
    itself unavailable instead of crashing the whole backend)."""

    if _override is not None:
        return _override

    from app.crew.models import configured_models

    model = model or configured_models()[0]

    if model not in _llms:
        with _lock:
            if model not in _llms:
                from crewai import LLM

                api_key = os.getenv("GROQ_API_KEY")

                if not api_key:
                    raise RuntimeError("GROQ_API_KEY is not configured.")

                _limit_provider_retries()

                _llms[model] = LLM(
                    model=model,
                    provider="openai",
                    api_key=api_key,
                    base_url=os.getenv("CREW_BASE_URL", "https://api.groq.com/openai/v1"),
                    temperature=0.0,
                    # Groq counts max_tokens toward the per-minute limit up
                    # front, so a smaller value also leaves more headroom.
                    max_tokens=int(os.getenv("CREW_MAX_TOKENS", "600")),
                    reasoning_effort="low",
                    max_retries=0,
                )

    return _llms[model]


def set_crew_llm(llm):
    """Replace the agent model (tests). None restores the configured models."""

    global _override

    _override = llm
    _llms.clear()

    from app.crew.models import reset_chain

    reset_chain()
