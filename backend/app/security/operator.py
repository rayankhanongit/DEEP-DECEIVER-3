"""
Operator access control.

The honeypot only works if the person on the other side of the chat cannot
see the defence. Everything that reveals it (detection details, security
events, alerts, Red Team, SOC data) is therefore restricted to the
*operator*, who proves identity with the OPERATOR_TOKEN from `.env`.

If OPERATOR_TOKEN is not configured nobody is an operator: chat responses
are always sanitised and the operator endpoints answer 503.
"""

import os
import secrets

from fastapi import Header, HTTPException, Query


def _expected() -> str:
    return os.getenv("OPERATOR_TOKEN", "").strip()


def is_operator(token: str | None) -> bool:
    expected = _expected()

    if not expected or not token:
        return False

    return secrets.compare_digest(token, expected)


def require_operator(
    x_operator_token: str | None = Header(default=None),
    token: str | None = Query(default=None),
):
    """FastAPI dependency. `token` query param exists for EventSource,
    which cannot set headers."""

    if not _expected():
        raise HTTPException(
            status_code=503,
            detail="OPERATOR_TOKEN is not configured.",
        )

    if not is_operator(x_operator_token or token):
        raise HTTPException(status_code=401, detail="Operator token required.")
