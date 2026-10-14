import json
import math
from pathlib import Path

from fastapi import APIRouter, Depends

from app.security.operator import require_operator

router = APIRouter(prefix="/soc", tags=["SOC"], dependencies=[Depends(require_operator)])

RESULTS = Path(__file__).resolve().parents[3] / "validation" / "results"

MODES = [("filter", "Fast Filter"), ("sensors", "Filter + embeddings"), ("agents", "CrewAI agents")]


def wilson(k: int, n: int, z: float = 1.96) -> list[float] | None:
    if n == 0:
        return None

    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))

    return [round((c - m) / d, 3), round((c + m) / d, 3)]


@router.get("/benchmark")
def benchmark():
    """Held-out detection results as written by validation/evaluate.py."""

    rows = []

    for key, label in MODES:
        path = RESULTS / f"eval_{key}_heldout.json"

        if not path.exists():
            continue

        d = json.loads(path.read_text(encoding="utf-8"))
        tp, fn, fp, tn = d["tp"], d["fn"], d["fp"], d["tn"]

        rows.append({
            "mode": key,
            "label": label,
            "attacks": tp + fn,
            "benign": fp + tn,
            "recall": d["recall"],
            "recall_ci": wilson(tp, tp + fn),
            "false_positive_rate": d["false_positive_rate"],
            "fpr_ci": wilson(fp, fp + tn),
            "errors": d.get("errors", 0),          # cases the model never answered
            "latency_ms": d.get("latency_ms"),
        })

    return {"rows": rows}
