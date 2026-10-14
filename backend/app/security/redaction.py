"""
Redaction and truncation helpers.

Security events must never contain API keys, tokens, passwords or large
verbatim prompts, so everything that is stored or logged goes through
`safe_excerpt`.
"""

import re


_SECRET_PATTERNS = [
    # Provider-style API keys (Groq, OpenAI, Anthropic, GitHub, Slack ...)
    re.compile(r"\bgsk_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),

    # Authorization headers / bearer tokens
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{12,}=*"),

    # JWTs
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),

    # key=value style secrets
    re.compile(
        r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)"
        r"\s*[:=]\s*[^\s,;\"']+"
    ),
]

_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")

DEFAULT_MAX_CHARS = 240


def redact(text: str) -> str:
    """Replace secrets and e-mail addresses with placeholders."""

    if not text:
        return ""

    redacted = str(text)

    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)

    redacted = _EMAIL.sub("[EMAIL]", redacted)

    return redacted


def safe_excerpt(text: str, max_chars: int = DEFAULT_MAX_CHARS) -> str:
    """Redact, collapse whitespace and truncate."""

    cleaned = " ".join(redact(text).split())

    if len(cleaned) > max_chars:
        return cleaned[: max_chars - 1] + "…"

    return cleaned
