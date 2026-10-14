import logging

from fastapi import APIRouter, Header
from pydantic import BaseModel, Field

from app.security.operator import is_operator
from app.services import sessions
from app.services.pipeline import pipeline

router = APIRouter()

logger = logging.getLogger("deep_deceiver.chat")


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=8000)

    # A server-issued session token. Anything else (missing, unsigned,
    # forged) is ignored and a new session is issued.
    session_id: str | None = Field(default=None, max_length=200)

    # Optional recent turns used to restore context after a server restart.
    history: list[dict] | None = Field(default=None, max_length=40)


def chat(request: ChatRequest, session_id: str | None = None) -> dict:
    """
    Full pipeline. Returns everything (detection, security, decoy ...).
    Anything facing untrusted users must go through `chat_endpoint`, which
    strips the response down to what a normal chat would show.

    `session_id` is an already-resolved internal id; the HTTP endpoint
    resolves the client's signed token to it.
    """

    if session_id is None:
        session_id, _token = sessions.resolve(request.session_id)

    return pipeline.process(request.message, session_id, request.history)


def public_view(result: dict) -> dict:
    """
    What an ordinary (untrusted) chat client may see: the reply and the
    session id. No detection data, risk, alerts, routing or decoy details,
    so a contained attacker cannot tell the defence reacted.
    """

    return {
        "response": result["response"],
        "session": {"session_id": result["session"]["session_id"]},
    }


@router.post("/chat")
def chat_endpoint(
    request: ChatRequest,
    x_operator_token: str | None = Header(default=None),
):
    session_id, token = sessions.resolve(request.session_id)

    result = chat(request, session_id=session_id)

    # The client only ever holds the signed token, never the bare id.
    result["session"]["session_id"] = token

    if is_operator(x_operator_token):
        return result

    return public_view(result)
