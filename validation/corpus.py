"""
One normalised view over every validation dataset, with a deterministic
development / held-out split.

Tune detection thresholds, patterns and prompts on `dev` only. Report
numbers from `heldout`, which nothing may be tuned against; otherwise the
metrics measure memorisation, not detection.
"""

import difflib
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from adversarial_tests import ENCODED_TESTS, INDIRECT_TESTS
from attack_datasets import VALIDATION_DATASET as ATTACK_SET
from dataset import VALIDATION_DATASET as BASE_SET
from extended import HARD_NEGATIVES, NEW_ATTACKS
from extended2 import ATTACKS_2, HARD_NEGATIVES_2


# OWASP Top 10 for LLM Applications (2025), referenced by risk NAME because
# tools number the same risks differently. Only risks a prompt-injection
# gateway can address are covered; see validation/README for the scope.
OWASP_RISKS = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM07": "System Prompt Leakage",
}

OWASP_BY_CATEGORY = {
    "instruction_override": "LLM01",
    "roleplay_manipulation": "LLM01",
    "safety_bypass": "LLM01",
    "obfuscated_injection": "LLM01",
    "rot13_injection": "LLM01",
    "leetspeak_injection": "LLM01",
    "indirect_injection": "LLM01",
    "document_injection": "LLM01",
    "tool_output_injection": "LLM01",
    "retrieved_content_injection": "LLM01",
    "system_prompt_extraction": "LLM07",
    "credential_extraction": "LLM02",
    "data_exfiltration": "LLM02",
}


def _is_attack(case: dict) -> bool:
    if "expected_attack" in case:
        return bool(case["expected_attack"])

    return case.get("expected") == "attack"


def split_of(case_id: str) -> str:
    """Stable 60/40 split by id (not by content or order)."""

    bucket = int(hashlib.sha256(case_id.encode()).hexdigest()[:8], 16) % 10

    return "dev" if bucket < 6 else "heldout"


def _leaks_reference(text: str, threshold: float = 0.8) -> bool:
    """True if the case is a near-duplicate of a Sentry reference attack."""

    from app.agents.sentry import THREAT_PROMPTS

    lowered = text.lower()

    return any(
        difflib.SequenceMatcher(None, lowered, reference.lower()).ratio() >= threshold
        for reference in THREAT_PROMPTS
    )


def load_corpus() -> list[dict]:
    cases = []

    for source, rows in (
        ("base", BASE_SET),
        ("attack_datasets", ATTACK_SET),
        ("encoded", ENCODED_TESTS),
        ("indirect", INDIRECT_TESTS),
    ):
        for row in rows:
            cases.append({
                "id": f"{source}:{row['id']}",
                "text": row["text"].strip(),
                "attack": _is_attack(row),
                "category": row.get("category", "unknown"),
                "source": source,
            })

    for index, text in enumerate(HARD_NEGATIVES, start=1):
        cases.append({"id": f"hard_negative:{index:03d}", "text": text, "attack": False,
                      "category": "hard_negative", "source": "hard_negatives"})

    for case_id, category, text in NEW_ATTACKS:
        cases.append({"id": f"extended:{case_id}", "text": text, "attack": True,
                      "category": category, "source": "extended"})

    for case_id, category, text in ATTACKS_2:
        cases.append({"id": f"batch2:{case_id}", "text": text, "attack": True,
                      "category": category, "source": "batch2", "frozen_heldout": True})

    for index, text in enumerate(HARD_NEGATIVES_2, start=1):
        cases.append({"id": f"batch2_negative:{index:03d}", "text": text, "attack": False,
                      "category": "hard_negative", "source": "batch2", "frozen_heldout": True})

    seen, unique = set(), []

    for case in cases:
        if case["text"] not in seen:
            seen.add(case["text"])
            unique.append(case)

    for case in unique:
        case["split"] = split_of(case["id"])

        # Near-duplicates of the detector's own reference prompts are
        # development data by definition, never held-out evidence.
        if case.get("frozen_heldout"):
            case["split"] = "heldout"          # written after the prompts froze

        if case["attack"] and _leaks_reference(case["text"]):
            case["split"] = "dev"
            case["leaks_reference"] = True

        case["owasp"] = OWASP_BY_CATEGORY.get(case["category"]) if case["attack"] else None

    return unique


def load_external(path: str) -> list[dict]:
    """Load a public benchmark exported as JSONL, e.g. from deepset/
    prompt-injections or HackAPrompt: one object per line with `text` and a
    `label` (1/true/'injection'/'attack' = attack) or `attack` boolean."""

    cases = []

    for index, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue

        row = json.loads(line)
        label = row.get("attack", row.get("label"))

        attack = label in (1, True, "1", "true", "injection", "attack", "jailbreak")

        cases.append({
            "id": f"external:{index:05d}",
            "text": row["text"],
            "attack": attack,
            "category": row.get("category", "external"),
            "source": "external",
            "split": "heldout",
            "owasp": "LLM01" if attack else None,    # injection benchmarks: LLM01
        })

    return cases
