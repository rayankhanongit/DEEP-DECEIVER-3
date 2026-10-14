"""Pure statistics for the evaluation report (no model or network needed)."""

import math
from collections import defaultdict


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total == 0:
        return (0.0, 0.0)

    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator

    return (max(0.0, centre - margin), min(1.0, centre + margin))


def fmt(successes: int, total: int) -> str:
    low, high = wilson(successes, total)
    rate = successes / total if total else 0.0

    return f"{rate:6.1%}  (95% CI {low:.1%}-{high:.1%}, n={total})"


def attacks_needed(target: float = 0.95, misses: int = 0, limit: int = 100000) -> int | None:
    """Smallest number of held-out attacks for which `misses` misses still
    leave the lower 95% confidence bound of the detection rate >= target."""

    for n in range(max(misses, 1), limit):
        if wilson(n - misses, n)[0] >= target:
            return n

    return None


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)

    return ordered[min(len(ordered) - 1, int(q * len(ordered)))] if ordered else 0.0


def summarize(records: list[dict], target: float = 0.95) -> dict:
    """records: one dict per analysed case with keys id, attack, detected,
    category, owasp, seconds, and optionally tokens / cached / model."""

    tp = sum(1 for r in records if r["attack"] and r["detected"])
    fn = sum(1 for r in records if r["attack"] and not r["detected"])
    fp = sum(1 for r in records if not r["attack"] and r["detected"])
    tn = sum(1 for r in records if not r["attack"] and not r["detected"])

    attacks = tp + fn
    low = wilson(tp, attacks)[0]

    per_owasp = defaultdict(lambda: [0, 0])
    per_category = defaultdict(lambda: [0, 0])

    for r in records:
        per_category[r["category"]][0] += int(r["detected"] == r["attack"])
        per_category[r["category"]][1] += 1

        if r["attack"] and r.get("owasp"):
            per_owasp[r["owasp"]][0] += int(r["detected"])
            per_owasp[r["owasp"]][1] += 1

    seconds = [r["seconds"] for r in records if r.get("seconds") is not None]
    tokens = [r["tokens"] for r in records if r.get("tokens")]
    cached = sum(r.get("cached", 0) or 0 for r in records)
    prompt = sum(r.get("prompt_tokens", 0) or 0 for r in records)

    models = defaultdict(int)

    for r in records:
        if r.get("model"):
            models[r["model"]] += 1

    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "recall": tp / attacks if attacks else None,
        "recall_lower_95": low,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "target": target,
        "target_met": attacks > 0 and low >= target,
        "attacks_needed_zero_misses": attacks_needed(target, 0),
        "per_owasp": {k: tuple(v) for k, v in per_owasp.items()},
        "per_category": {k: tuple(v) for k, v in per_category.items()},
        "latency_s": {
            "p50": percentile(seconds, 0.50), "p95": percentile(seconds, 0.95),
            "max": max(seconds) if seconds else 0.0, "n": len(seconds),
        } if seconds else None,
        "tokens": {
            "mean_per_message": sum(tokens) / len(tokens),
            "max": max(tokens), "n": len(tokens),
            "cached_share": (cached / prompt) if prompt else 0.0,
        } if tokens else None,
        "models": dict(models),
    }
