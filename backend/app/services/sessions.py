"""
Server-issued session identities and honeypot containment state.

Session ids
-----------
Clients never choose their own session id. The server issues
`<id>.<signature>` tokens (HMAC-SHA256 with SESSION_SECRET). A missing or
forged token simply gets a brand-new session, so an attacker cannot join,
poison or impersonate another user's session (and no shared "default"
session exists).

Containment
-----------
A session the agents judged hostile is moved to the honeypot. Containment is
sticky (switching back mid-conversation would be a tell) but not permanent:
it expires CONTAINMENT_TTL_SECONDS after the last hostile verdict, ends
after CONTAINMENT_CLEAN_TURNS consecutive benign verdicts, and an operator
can release a session explicitly.
"""

import base64
import hashlib
import hmac
import os
import secrets
import threading
import time
import uuid

from app.utils.bounded import BoundedStore

_SECRET = None
_SECRET_LOCK = threading.Lock()


def _secret() -> bytes:
    global _SECRET

    configured = os.getenv("SESSION_SECRET", "").strip()

    if configured:
        return configured.encode()

    with _SECRET_LOCK:
        if _SECRET is None:
            # No configured secret: tokens are valid until restart only.
            _SECRET = secrets.token_bytes(32)

        return _SECRET


def _sign(session_id: str) -> str:
    digest = hmac.new(_secret(), session_id.encode(), hashlib.sha256).digest()

    return base64.urlsafe_b64encode(digest[:16]).decode().rstrip("=")


def issue_token(session_id: str | None = None) -> tuple[str, str]:
    """Returns (session_id, token)."""

    session_id = session_id or uuid.uuid4().hex

    return session_id, f"{session_id}.{_sign(session_id)}"


def verify_token(token: str | None) -> str | None:
    """Session id for a valid token, else None."""

    if not token or "." not in token:
        return None

    session_id, _, signature = token.rpartition(".")

    if not session_id or not hmac.compare_digest(signature, _sign(session_id)):
        return None

    return session_id


def resolve(client_value: str | None) -> tuple[str, str]:
    """(session_id, token): the client's session if its token is valid,
    otherwise a freshly issued one."""

    session_id = verify_token(client_value)

    if session_id:
        return session_id, client_value

    return issue_token()


# ----------------------------------------------------------------------
# Containment
# ----------------------------------------------------------------------

def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


class ContainmentRegistry:

    def __init__(self, clock=time.monotonic, max_sessions: int = 20000):
        self._clock = clock
        self._state = BoundedStore(max_items=max_sessions)
        self._lock = threading.Lock()

    @staticmethod
    def ttl_seconds() -> float:
        return _env_float("CONTAINMENT_TTL_SECONDS", 900.0)

    @staticmethod
    def clean_turns() -> int:
        return int(_env_float("CONTAINMENT_CLEAN_TURNS", 3))

    # --------------------------------------------------

    def is_contained(self, session_id: str) -> bool:
        with self._lock:
            state = self._state.get(session_id)

            if state is None:
                return False

            if state["until"] <= self._clock():
                self._state.pop(session_id, None)
                return False

            return True

    def contain(self, session_id: str, reason: str = "agent_verdict"):
        with self._lock:
            now = self._clock()
            state = self._state.get(session_id) or {"since": now, "hostile_turns": 0}

            state.update(
                until=now + self.ttl_seconds(),
                clean_streak=0,
                reason=reason,
            )
            state["hostile_turns"] += 1

            self._state[session_id] = state

    def record_verdict(self, session_id: str, hostile: bool) -> bool:
        """Update a contained session with the latest agent verdict.
        Returns True if the session is still contained afterwards."""

        if hostile:
            self.contain(session_id, "agent_verdict")
            return True

        with self._lock:
            state = self._state.get(session_id)

            if state is None or state["until"] <= self._clock():
                self._state.pop(session_id, None)
                return False

            state["clean_streak"] += 1
            limit = self.clean_turns()

            if limit > 0 and state["clean_streak"] >= limit:
                self._state.pop(session_id, None)
                return False

            return True

    def release(self, session_id: str) -> bool:
        with self._lock:
            return self._state.pop(session_id, None) is not None

    def snapshot(self) -> list[dict]:
        now = self._clock()

        with self._lock:
            return [
                {
                    "session_id": sid,
                    "hostile_turns": s["hostile_turns"],
                    "clean_streak": s["clean_streak"],
                    "expires_in_seconds": max(0, int(s["until"] - now)),
                    "reason": s["reason"],
                }
                for sid, s in self._state.items()
                if s["until"] > now
            ]


containment = ContainmentRegistry()
