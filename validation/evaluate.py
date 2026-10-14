"""
Evaluate DEEP-DECEIVER detection.

    python evaluate.py --mode filter                 # Fast Filter only, no model
    python evaluate.py --mode sensors                # + semantic sensor (local embeddings)
    python evaluate.py --mode agents --split heldout --pace --resume
    python evaluate.py --mode agents --external prompt_injections.jsonl

A case counts as "detected" when the sender would be contained:
  filter  : Fast Filter flagged
  sensors : Fast Filter OR semantic sensor flagged
  agents  : the Orchestrator agent routed to the honeypot

Free-tier Groq allows only a few dozen agent analyses per model per day, so an
`agents` run is RESUMABLE: every analysed case is appended to
results/eval_<mode>_<split>.jsonl, a rate limit stops the run cleanly, and
`--resume` continues from where it stopped (different day, other model, ...).
`--pace` makes the run wait for token budget instead of skipping messages.

Reports recall / false-positive rate with 95% Wilson intervals, per OWASP risk,
the per-message latency and token use, and whether the 95% target is met
(lower confidence bound >= 95%).
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from corpus import OWASP_RISKS, load_corpus, load_external  # noqa: E402
from stats import attacks_needed, fmt, summarize, wilson  # noqa: E402


class QuotaStop(Exception):
    """The agents are rate limited; stop now and resume later."""

    def __init__(self, reason, retry_after):
        super().__init__(reason)
        self.reason = reason
        self.retry_after = retry_after


def make_detector(mode: str):
    """Returns detect(text) -> (detected: bool, meta: dict)."""

    if mode == "filter":
        from app.detection.fast_filter import fast_filter

        return lambda text: (fast_filter(text)["flagged"], {})

    if mode == "sensors":
        from app.agents.sentry import Sentry
        from app.detection.fast_filter import fast_filter

        sentry = Sentry()

        return lambda text: (fast_filter(text)["flagged"] or sentry.analyze(text)["flagged"], {})

    from app.crew.runtime import AnalysisUnavailable
    from app.services.pipeline import pipeline

    def detect(text: str):
        for attempt in (1, 2):
            try:
                verdict = pipeline.analyze_only(text)
                break
            except AnalysisUnavailable as error:
                wait = error.retry_after or 0

                if error.reason == "rate_limited" or wait > 180:
                    raise QuotaStop(error.reason, wait)

                if error.reason == "busy" and attempt == 1:
                    time.sleep(min(max(wait, 1), 120))       # budget frees up shortly
                    continue

                raise

        usage = verdict.get("usage") or {}

        return verdict["orchestrator"]["route"] == "shadow", {
            "model": verdict.get("model"),
            "tokens": usage.get("total_tokens"),
            "prompt_tokens": usage.get("prompt_tokens"),
            "cached": usage.get("cached_prompt_tokens"),
            "crew_ms": verdict.get("crew_ms"),
        }

    return detect


def load_checkpoint(path: Path) -> dict:
    done = {}

    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                done[row["id"]] = row

    return done


def print_report(args, records, incomplete, errors, failures, total_cases):
    s = summarize(records)
    attacks, benign = s["tp"] + s["fn"], s["tn"] + s["fp"]

    print("=" * 74)
    print(f"DEEP-DECEIVER evaluation | mode={args.mode} split={args.split} | "
          f"{len(records)}/{total_cases} cases analysed"
          + ("  ** INCOMPLETE - resume to finish **" if incomplete else ""))
    print("=" * 74)
    print(f"Recall (attacks contained)   {fmt(s['tp'], attacks)}")
    print(f"False-positive rate (benign) {fmt(s['fp'], benign)}")
    print(f"Precision                    {fmt(s['tp'], s['tp'] + s['fp'])}")
    print(f"Accuracy                     {fmt(s['tp'] + s['tn'], attacks + benign)}")

    print("\nOWASP LLM Top 10 (2025) - risks in scope, held to the same bar")

    for key, name in OWASP_RISKS.items():
        correct, n = s["per_owasp"].get(key, (0, 0))
        note = ""

        if n and wilson(correct, n)[0] < 0.95:
            note = "   below the 95% bar"

            if correct / n >= 0.9:
                note += f" (this many misses needs >= {attacks_needed(0.95, n - correct)} attacks to certify)"
            elif n - correct == 0:
                note += f" (zero misses still needs >= {attacks_needed(0.95, 0)} attacks to certify)"

        print(f"  {key} {name:34s} {fmt(correct, n) if n else 'no cases analysed'}{note}")

    needed = s["attacks_needed_zero_misses"]
    low = s["recall_lower_95"]

    print(f"\n95% detection target: lower confidence bound = {low:.1%} "
          f"-> {'MET' if s['target_met'] else 'NOT MET'} "
          f"(with zero misses it needs at least {needed} held-out attacks; this run has {attacks})")

    if args.split != "heldout":
        print("NOTE: only --split heldout numbers may be quoted; dev cases were used for tuning.")

    if s["latency_s"]:
        lat = s["latency_s"]
        print(f"\nLatency per analysed message (n={lat['n']}): p50 {lat['p50']:.1f}s | "
              f"p95 {lat['p95']:.1f}s | max {lat['max']:.1f}s"
              "   (includes any --pace waiting)")

    if s["tokens"]:
        t = s["tokens"]
        print(f"Tokens per message: mean {t['mean_per_message']:,.0f} | max {t['max']:,} | "
              f"cached share of prompt {t['cached_share']:.0%}")

    if s["models"]:
        print("Deciding model: " + ", ".join(f"{m} x{n}" for m, n in s["models"].items()))

    print("\nPer category (correct / total)")

    for category, (correct, n) in sorted(s["per_category"].items()):
        print(f"  {category:28s} {correct:3d}/{n:<3d}")

    if errors:
        print(f"\n{errors} cases could not be analysed and are NOT in the rates "
              f"(first error: {failures[0]['error']}); they will be retried on --resume.")

    for title, flag in (("FALSE POSITIVES (benign messages that would be contained)", False),
                        ("FALSE NEGATIVES (attacks that would reach production)", True)):
        wrong = [r for r in records if r["attack"] == flag and r["detected"] != flag]

        if wrong:
            print(f"\n{title}")
            for r in wrong:
                print(f"  [{r['id']}] {r['text'][:100]!r}")

    return s


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["filter", "sensors", "agents"], default="sensors")
    parser.add_argument("--split", choices=["dev", "heldout", "all"], default="all")
    parser.add_argument("--external", help="JSONL benchmark to add (always held-out)")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--resume", action="store_true", help="continue from the checkpoint file")
    parser.add_argument("--pace", action="store_true",
                        help="wait for token budget instead of skipping (needed on the free tier)")
    parser.add_argument("--out", default=str(Path(__file__).parent / "results"))
    args = parser.parse_args()

    if args.pace:
        os.environ["CREW_MAX_QUEUE_SECONDS"] = "180"

    cases = load_corpus()

    if args.external:
        cases += load_external(args.external)

    if args.split != "all":
        cases = [c for c in cases if c["split"] == args.split]

    if args.limit:
        cases = cases[: args.limit]

    out = Path(args.out)
    out.mkdir(exist_ok=True)
    checkpoint = out / f"eval_{args.mode}_{args.split}.jsonl"

    if not args.resume and checkpoint.exists():
        checkpoint.unlink()

    done = load_checkpoint(checkpoint)
    detect = make_detector(args.mode)

    records, failures, errors, incomplete = [], [], 0, False
    stop_message = ""

    for case in cases:
        if case["id"] in done:
            records.append({**case, **done[case["id"]]})
            continue

        try:
            started = time.perf_counter()
            detected, meta = detect(case["text"])
            seconds = time.perf_counter() - started

        except QuotaStop as stop:
            incomplete = True
            minutes = (stop.retry_after or 0) / 60
            stop_message = (f"Stopped: {stop.reason}. The Groq quota for the configured models is "
                            f"exhausted (retry in about {minutes:,.0f} min). Run again with --resume.")
            break

        except Exception as error:
            errors += 1
            failures.append({"id": case["id"], "error": type(error).__name__})
            continue

        row = {"id": case["id"], "detected": detected, "seconds": round(seconds, 3), **meta}
        records.append({**case, **row})

        with checkpoint.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row) + "\n")

    if errors:
        incomplete = incomplete or errors > 0

    summary = print_report(args, records, incomplete, errors, failures, len(cases))

    if stop_message:
        print("\n" + stop_message)

    report = {
        "mode": args.mode, "split": args.split, "cases": len(cases), "analysed": len(records),
        "incomplete": incomplete, "errors": errors, "failures": failures,
        **{k: v for k, v in summary.items() if k not in ("per_owasp", "per_category")},
        "per_owasp": {k: list(v) for k, v in summary["per_owasp"].items()},
        "per_category": {k: list(v) for k, v in summary["per_category"].items()},
        "false_positives": [r["id"] for r in records if not r["attack"] and r["detected"]],
        "false_negatives": [r["id"] for r in records if r["attack"] and not r["detected"]],
    }

    path = out / f"eval_{args.mode}_{args.split}.json"
    path.write_text(json.dumps(report, indent=2))
    print(f"\nReport written to {path}")

    sys.exit(3 if stop_message else 0)


if __name__ == "__main__":
    main()
