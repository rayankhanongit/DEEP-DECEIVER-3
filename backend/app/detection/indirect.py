import re


INDIRECT_CONTEXT_PATTERNS = [
    r"\bimportant\s+note\s+for\s+the\s+ai\b",
    r"\binternal\s+processing\s+instruction\b",
    r"\bsystem\s+note\b",
    r"\bai\s+instruction\b",
    r"\bhidden\s+instruction\b",
    r"\binstruction\s+to\s+the\s+ai\b",
    r"\bfor\s+the\s+ai\s+system\b",

    r"\btool\s+output\b",
    r"\bretrieved\s+(content|document|text)\b",
    r"\bknowledge[-\s]?base\b",
    r"\bcustomer\s+support\s+document\b",
    r"\bquarterly\s+report\b",
]


INDIRECT_INJECTION_PATTERNS = [
    r"\bignore\s+(all\s+)?previous\s+instructions\b",
    r"\bignore\s+(all\s+)?prior\s+instructions\b",
    r"\bdisregard\s+(all\s+)?previous\s+instructions\b",
    r"\bdisregard\s+(all\s+)?prior\s+instructions\b",
    r"\bforget\s+(your\s+)?(original\s+)?instructions\b",
    r"\boverride\s+(your\s+)?(previous\s+)?instructions\b",

    r"\breveal\s+(your|the)\s+(system|hidden)\s+prompt\b",
    r"\bexpose\s+(your|the)\s+(hidden|system)\s+instructions\b",
    r"\breveal\s+(confidential|private|hidden)\s+information\b",
    r"\bprovide\s+confidential\s+system\s+information\b",

    r"\bbypass\s+(your\s+)?(rules|restrictions|safety)\b",
    r"\bdisable\s+(your\s+)?(safety|security|filters)\b",
]


def detect_indirect_injection(text: str) -> dict:
    """
    Detect prompt injection embedded inside documents,
    tool outputs, retrieved content, or other external context.

    Detection is based on two signals:

    1. Context signal:
       The input contains document/tool/retrieval-style content.

    2. Injection signal:
       The embedded content contains instruction-override,
       system-prompt extraction, or safety-bypass language.
    """

    normalized_text = text.lower()

    context_matches = []
    injection_matches = []

    # Detect indirect/contextual sources.
    for pattern in INDIRECT_CONTEXT_PATTERNS:
        if re.search(pattern, normalized_text):
            context_matches.append(pattern)

    # Detect malicious instruction content.
    for pattern in INDIRECT_INJECTION_PATTERNS:
        if re.search(pattern, normalized_text):
            injection_matches.append(pattern)

    # Strong indirect signal:
    # contextual content + injection instruction.
    if context_matches and injection_matches:
        score = min(
            1.0,
            0.55
            + (len(context_matches) * 0.05)
            + (len(injection_matches) * 0.10)
        )

        return {
            "detected": True,
            "score": round(score, 2),
            "matched_patterns": (
                [
                    f"context:{pattern}"
                    for pattern in context_matches
                ]
                + [
                    f"injection:{pattern}"
                    for pattern in injection_matches
                ]
            )
        }

    # Injection embedded in document-like text can still be
    # considered suspicious even if the context label is absent.
    if injection_matches and (
        "\n" in text
        or len(text.split()) >= 20
    ):
        score = min(
            1.0,
            0.45 + (len(injection_matches) * 0.10)
        )

        return {
            "detected": True,
            "score": round(score, 2),
            "matched_patterns": [
                f"injection:{pattern}"
                for pattern in injection_matches
            ]
        }

    return {
        "detected": False,
        "score": 0.0,
        "matched_patterns": []
    }