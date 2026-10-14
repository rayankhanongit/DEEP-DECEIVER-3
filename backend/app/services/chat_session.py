"""
Conversation memory and the production reply path.

A normal chatbot needs context, so every session keeps its recent turns
server-side. If the server has no history for a session (for example after a
backend restart) the client may send its own recent messages once to restore
it; they are validated and capped.
"""

import logging
import re
import threading
import time

from app.utils.bounded import BoundedStore

logger = logging.getLogger("deep_deceiver.chat")

MAX_TURNS = 20
MAX_CONTENT = 4000

# Bounded: idle sessions expire, and the store never exceeds MAX_SESSIONS.
MAX_SESSIONS = 5000
SESSION_TTL_SECONDS = 6 * 3600

_histories = BoundedStore(max_items=MAX_SESSIONS, ttl_seconds=SESSION_TTL_SECONDS)
_lock = threading.Lock()


def seed_history(session_id: str, history: list[dict] | None):
    """Restore context from the client only when the server has none."""

    if not history:
        return

    with _lock:
        if _histories.get(session_id):
            return

        clean = []

        for item in history[-MAX_TURNS:]:
            role = item.get("role")
            content = str(item.get("content", ""))[:MAX_CONTENT]

            if role in ("user", "assistant") and content.strip():
                clean.append({"role": role, "content": content})

        _histories[session_id] = clean


def get_history(session_id: str) -> list[dict]:
    """Copy of the session's conversation so far (oldest first)."""

    with _lock:
        return list(_histories.get(session_id) or [])


def reset(session_id: str | None = None):
    with _lock:
        if session_id is None:
            _histories.clear()
        else:
            _histories.pop(session_id, None)


def _retry_after(error: Exception) -> float:
    match = re.search(r"try again in ([0-9.]+)\s*(ms|s)", str(error))

    if not match:
        return 2.0

    value = float(match.group(1))

    return value / 1000 if match.group(2) == "ms" else value


def production_reply(
    session_id: str,
    message: str,
    generate=None,
    system_prompt: str | None = None,
) -> str:
    """
    Answer with the production model using the session's history.

    Quick path: one model call with low reasoning effort. On a rate limit it
    waits the (short) time Groq asks for and retries once.
    """

    if generate is None:
        from app.services.llm import generate_chat as generate

    with _lock:
        history = _histories.setdefault(session_id, [])
        turns = history[-MAX_TURNS:] + [{"role": "user", "content": message[:MAX_CONTENT]}]

    last_error = None

    for attempt in range(2):
        try:
            kwargs = {"system_prompt": system_prompt} if system_prompt else {}

            text = (generate(
                turns,
                temperature=0.7,
                max_tokens=1500,
                reasoning_effort="low",
                **kwargs,
            ) or "").strip()

            if text:
                with _lock:
                    history.append({"role": "user", "content": message[:MAX_CONTENT]})
                    history.append({"role": "assistant", "content": text})
                    del history[:-MAX_TURNS]

                return text

        except Exception as error:
            last_error = error
            wait = _retry_after(error)

            logger.warning("LLM call failed (%s)", type(error).__name__)

            if attempt == 0 and type(error).__name__ == "RateLimitError" and wait <= 10:
                time.sleep(wait)
                continue

            break

    raise RuntimeError("model unavailable") from last_error
