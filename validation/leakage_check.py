"""
Warn when validation cases are near-duplicates of the Sentry's reference
attack prompts (the detector would then be graded on its own training data).

    python leakage_check.py [--threshold 0.8]
"""

import argparse
import difflib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.agents.sentry import THREAT_PROMPTS  # noqa: E402
from corpus import load_corpus  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--threshold", type=float, default=0.8)
    args = parser.parse_args()

    leaks = []

    for case in load_corpus():
        if not case["attack"]:
            continue

        for reference in THREAT_PROMPTS:
            ratio = difflib.SequenceMatcher(None, case["text"].lower(), reference.lower()).ratio()

            if ratio >= args.threshold:
                leaks.append((ratio, case["id"], case["text"][:80], reference))

    for ratio, case_id, text, reference in sorted(leaks, reverse=True):
        print(f"{ratio:.2f}  {case_id}\n      case:      {text!r}\n      reference: {reference!r}")

    print(f"\n{len(leaks)} validation attacks are >= {args.threshold:.0%} similar to a Sentry reference prompt.")
    print("Move these to the dev split, or exclude them from reported (held-out) numbers.")

    return 1 if leaks else 0


if __name__ == "__main__":
    sys.exit(main())
