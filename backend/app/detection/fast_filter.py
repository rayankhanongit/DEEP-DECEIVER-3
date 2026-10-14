"""
Fast Filter: cheap, deterministic *sensor*.

It does not decide anything. Its output is evidence handed to the CrewAI
agents (see app/crew), which weigh it against the rest of the message and the
conversation. Strong patterns are unambiguous attack phrasing; weak patterns
(``act as a ...``, ``system prompt``) are very common in benign messages, so
alone they are reported as `weak_matches` and do not raise the flag.
"""

import re

from app.detection.indirect import detect_indirect_injection
from app.detection.obfuscation import detect_obfuscation

_RESIDUE = r"(?:\s+(?:of|the|your|my|all|any|these|those))*"

STRONG_PATTERNS = [
    rf"\b(ignore|disregard|forget|override|overwrite){_RESIDUE}\s+(previous|prior|above|earlier|original|preceding)\s+(instructions?|rules|prompts?|directives|guidelines)\b",
    r"\boverride\s+(your|the)\s+instructions\b",
    r"\bforget\s+(your\s+)?(original\s+)?instructions\b",
    r"\b(reveal|show|print|display|repeat|leak|output|tell\s+me)\s+(me\s+)?(your|the)\s+(?:(?:system|hidden|initial|original|secret)\s+){1,2}(prompt|instructions?|message)\b",
    r"\bbypass\s+(your\s+|the\s+)?(rules|restrictions|safety|guardrails|filters)\b",
    r"\bdisable\s+(your\s+|the\s+)?(safety|security|filters|guardrails)\b",
    r"\bremove\s+(your\s+)?(restrictions|limitations)\b",
    r"\b(you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as)\s+(an?\s+)?(unrestricted|uncensored|unfiltered|jailbroken|evil)\b",
    r"\b(enable|activate|switch\s+to|enter)\s+(developer|god)\s+mode\b(?!.{0,60}\b(phone|android|ios|iphone|usb|debugging|chrome|browser|windows|macos|xcode|app)\b)",
    r"\bdo\s+anything\s+now\b",
]

WEAK_PATTERNS = [
    r"\byou\s+are\s+now\s+(a|an)\b",
    r"\bact\s+as\s+(a|an)\b",
    r"\bpretend\s+to\s+be\b",
    r"\broleplay\s+as\b",
    r"\bsystem\s+prompt\b",
    r"\bdeveloper\s+message\b",
    r"\bsystem\s+message\b",
    r"\b(developer|god)\s+mode\b",
    r"\bjailbreak\b",
]

CREDENTIAL_PATTERNS = [
    r"\b(give|provide|show|reveal|send|tell|display|print)\b.*\b(password|passcode|credentials?)\b",
    r"\b(give|provide|show|reveal|send|tell|display|print)\b.*\b(api\s*key|access\s*token|secret\s*key)\b",
    r"\b(give|provide|show|reveal|send|tell|display|print)\b.*\b(admin|administrator|root)\b.*\b(password|credentials?|token)\b",
    r"\b(get|obtain|retrieve|extract|steal)\b.*\b(password|credentials?|api\s*key|access\s*token|secret)\b",
    r"\b(database|db)\b.*\b(credentials?|password|username|token)\b",
]

# Ordinary engineering / support talk about credentials.
CREDENTIAL_BENIGN_CUES = re.compile(
    r"\b(hash(ed|es|ing)?|salt(ed|ing)?|bcrypt|argon2?|reset|rotat(e|ion)|"
    r"stor(e|ed|ing)|secur(e|ely|ity)|best\s+practices?|polic(y|ies)|"
    r"password\s+manager|forgot(ten)?|strength|environment\s+variables?|env\s+vars?|"
    r"\.env|secrets?\s+manager|vault|kubernetes|docker|oauth|"
    r"in\s+(python|node(\.js)?|java(script)?|go|rust|c#|php|ruby))\b"
)


def _search_all(patterns: list[str], text: str) -> list[str]:
    return [p for p in patterns if re.search(p, text)]


def fast_filter(text: str) -> dict:
    normalized = text.lower().strip()

    obfuscation = detect_obfuscation(text)
    decoded = (obfuscation["decoded_text"] or "").lower().strip()

    strong = _search_all(STRONG_PATTERNS, normalized)
    weak = _search_all(WEAK_PATTERNS, normalized)

    matched = list(strong)

    if decoded:
        matched += [f"obfuscated:{p}" for p in _search_all(STRONG_PATTERNS, decoded)]
        weak += _search_all(WEAK_PATTERNS, decoded)

    # Credential extraction (not when the message is ordinary
    # password-engineering talk).
    if not CREDENTIAL_BENIGN_CUES.search(normalized):
        matched += [f"credential:{p}" for p in _search_all(CREDENTIAL_PATTERNS, normalized)]

    indirect = detect_indirect_injection(text)

    if indirect["detected"]:
        matched += [f"indirect:{p}" for p in indirect["matched_patterns"]]

    unique_weak = sorted(set(weak))

    # Two independent weak signals together are worth a flag.
    if not matched and len(unique_weak) >= 2:
        matched = [f"weak:{p}" for p in unique_weak]

    if not matched:
        return {
            "flagged": False,
            "score": 0.0,
            "matched_patterns": [],
            "weak_matches": unique_weak,
            "obfuscation": obfuscation,
            "indirect": indirect,
        }

    score = min(1.0, 0.30 + len(matched) * 0.15)

    return {
        "flagged": True,
        "score": round(score, 2),
        "matched_patterns": matched,
        "weak_matches": unique_weak,
        "obfuscation": obfuscation,
        "indirect": indirect,
    }
