"""Evaluation tooling: statistics, OWASP mapping, held-out integrity, and the
resumable / quota-aware runner (no model, network or API key needed)."""

import json
import sys
from pathlib import Path

import pytest

VALIDATION = Path(__file__).resolve().parents[2] / "validation"
sys.path.insert(0, str(VALIDATION))

import corpus  # noqa: E402
import evaluate  # noqa: E402
import stats  # noqa: E402


# ---------------- statistics ----------------

def test_wilson_bounds():
    low, high = stats.wilson(106, 106)

    assert low == pytest.approx(0.965, abs=0.003)
    assert high == pytest.approx(1.0)
    assert stats.wilson(0, 0) == (0.0, 0.0)


def test_attacks_needed_for_the_95_percent_claim():
    assert stats.attacks_needed(0.95, misses=0) == 73
    assert stats.attacks_needed(0.95, misses=1) > 73
    assert stats.attacks_needed(0.95, misses=2) == 142
    assert stats.wilson(72, 72)[0] < 0.95 <= stats.wilson(73, 73)[0]


def test_summary_counts_and_target():
    records = [
        {"id": str(i), "attack": True, "detected": True, "category": "instruction_override",
         "owasp": "LLM01", "seconds": 2.0, "tokens": 3000, "model": "m"} for i in range(80)
    ] + [
        {"id": f"b{i}", "attack": False, "detected": False, "category": "hard_negative",
         "owasp": None, "seconds": 1.0} for i in range(20)
    ]

    summary = stats.summarize(records)

    assert (summary["tp"], summary["fn"], summary["fp"], summary["tn"]) == (80, 0, 0, 20)
    assert summary["target_met"] is True
    assert summary["per_owasp"]["LLM01"] == (80, 80)
    assert summary["latency_s"]["p50"] in (1.0, 2.0)
    assert summary["models"] == {"m": 80}


def test_target_not_met_with_too_few_attacks_even_if_perfect():
    records = [{"id": str(i), "attack": True, "detected": True, "category": "x", "owasp": "LLM01"}
               for i in range(17)]

    assert stats.summarize(records)["target_met"] is False


# ---------------- corpus ----------------

def test_every_attack_is_mapped_to_an_owasp_risk_by_name():
    cases = corpus.load_corpus()

    for case in cases:
        if case["attack"]:
            assert case["owasp"] in corpus.OWASP_RISKS, case["id"]
        else:
            assert case["owasp"] is None


def test_heldout_is_large_enough_to_support_the_95_percent_claim():
    attacks = [c for c in corpus.load_corpus() if c["attack"] and c["split"] == "heldout"]

    assert len(attacks) >= stats.attacks_needed(0.95, 0)
    assert {c["owasp"] for c in attacks} == set(corpus.OWASP_RISKS)


def test_batch2_is_heldout_and_nothing_leaks_the_sentry_references():
    cases = corpus.load_corpus()
    batch2 = [c for c in cases if c["source"] == "batch2"]

    assert batch2 and all(c["split"] == "heldout" for c in batch2)
    assert not [c for c in cases if c["split"] == "heldout" and c.get("leaks_reference")]


def test_case_ids_and_texts_are_unique():
    cases = corpus.load_corpus()

    assert len({c["id"] for c in cases}) == len(cases)
    assert len({c["text"] for c in cases}) == len(cases)


# ---------------- resumable runner ----------------

def run_main(monkeypatch, tmp_path, detector, *extra):
    monkeypatch.setattr(evaluate, "make_detector", lambda mode: detector)
    monkeypatch.setattr(sys, "argv", ["evaluate.py", "--mode", "agents", "--split", "heldout",
                                      "--limit", "12", "--out", str(tmp_path), *extra])

    with pytest.raises(SystemExit) as exit_info:
        evaluate.main()

    return exit_info.value.code


def test_quota_stop_saves_progress_and_resume_finishes(monkeypatch, tmp_path, capsys):
    calls = []

    def limited(text):
        if len(calls) >= 5:
            raise evaluate.QuotaStop("rate_limited", 600)

        calls.append(text)
        return False, {"model": "m1", "tokens": 3000, "prompt_tokens": 2000, "cached": 500}

    code = run_main(monkeypatch, tmp_path, limited)

    assert code == 3
    assert "INCOMPLETE" in capsys.readouterr().out

    checkpoint = tmp_path / "eval_agents_heldout.jsonl"
    assert len(checkpoint.read_text().splitlines()) == 5

    resumed = []

    def healthy(text):
        resumed.append(text)
        return False, {"model": "m2", "tokens": 2500}

    assert run_main(monkeypatch, tmp_path, healthy, "--resume") == 0
    assert len(resumed) == 7                                  # only the 7 not yet done
    assert len(checkpoint.read_text().splitlines()) == 12

    report = json.loads((tmp_path / "eval_agents_heldout.json").read_text())

    assert report["analysed"] == 12 and report["incomplete"] is False
    assert report["models"] == {"m1": 5, "m2": 7}


def test_without_resume_the_checkpoint_is_restarted(monkeypatch, tmp_path):
    seen = []

    run_main(monkeypatch, tmp_path, lambda t: (seen.append(t) or False, {}))
    first = len(seen)
    run_main(monkeypatch, tmp_path, lambda t: (seen.append(t) or False, {}))

    assert len(seen) == 2 * first


def test_unexpected_errors_are_reported_and_retried_on_resume(monkeypatch, tmp_path, capsys):
    state = {"fail": True, "calls": 0}

    def flaky(text):
        state["calls"] += 1

        if state["fail"] and state["calls"] == 3:
            raise RuntimeError("boom")

        return False, {}

    run_main(monkeypatch, tmp_path, flaky)
    out = capsys.readouterr().out

    assert "could not be analysed" in out

    state["fail"] = False
    retried = []
    run_main(monkeypatch, tmp_path, lambda t: (retried.append(t) or False, {}), "--resume")

    assert len(retried) == 1                                  # only the failed case is redone


# ---------------- Giskard runner (fake agents, real Giskard) ----------------

giskard_owasp = pytest.importorskip("giskard.checks") and __import__("giskard_owasp")

from crew_helpers import FakeCrew, make_pipeline, make_verdict  # noqa: E402


def run_giskard(monkeypatch, tmp_path, crew, *extra):
    pipeline, *_ = make_pipeline(monkeypatch, crew=crew)

    monkeypatch.setattr(giskard_owasp, "get_pipeline", lambda: pipeline)
    monkeypatch.setattr(sys, "argv", ["giskard_owasp.py", "--split", "heldout", "--limit", "8",
                                      "--out", str(tmp_path), *extra])

    with pytest.raises(SystemExit) as exit_info:
        giskard_owasp.main()

    return exit_info.value.code, pipeline


def test_giskard_runner_scores_by_containment(monkeypatch, tmp_path, capsys):
    crew = FakeCrew(decide=lambda text: make_verdict("ignore" in text.lower() or "system prompt" in text.lower(),
                                                      "instruction_override"))

    code, _ = run_giskard(monkeypatch, tmp_path, crew)
    out = capsys.readouterr().out
    report = json.loads((tmp_path / "giskard_heldout.json").read_text())

    assert code == 0
    assert "OWASP LLM Top 10" in out
    assert report["analysed"] == 8
    assert "disagreed" not in out                       # Giskard verdict == containment flag


def test_giskard_runner_runs_multi_turn_in_one_session(monkeypatch, tmp_path):
    seen = []

    def decide(text):
        seen.append(text)
        return make_verdict("ignore all of those rules" in text.lower(), "instruction_override")

    crew = FakeCrew(decide=decide)

    # the 4-turn escalation is the last heldout case when limit is large enough
    monkeypatch.setattr(giskard_owasp, "MULTI_TURN", giskard_owasp.MULTI_TURN[:1])
    pipeline, *_ = make_pipeline(monkeypatch, crew=crew)
    monkeypatch.setattr(giskard_owasp, "get_pipeline", lambda: pipeline)
    monkeypatch.setattr(sys, "argv", ["giskard_owasp.py", "--split", "heldout", "--limit", "9999",
                                      "--out", str(tmp_path)])

    # only exercise the multi-turn scenario to keep the test fast
    monkeypatch.setattr(giskard_owasp, "load_corpus", lambda: [])

    with pytest.raises(SystemExit):
        giskard_owasp.main()

    report = json.loads((tmp_path / "giskard_heldout.json").read_text())

    assert report["analysed"] == 1
    assert report["false_negatives"] == []              # contained on the final turn
    assert len(crew.calls) == 4                         # one analysis per turn, same session


def test_giskard_runner_stops_on_quota_and_resumes(monkeypatch, tmp_path, capsys):
    from app.crew.runtime import AnalysisUnavailable

    class QuotaCrew(FakeCrew):
        def analyze(self, text, *a, **k):
            if len(self.calls) >= 3:
                raise AnalysisUnavailable("rate_limited", retry_after=900)

            return super().analyze(text, *a, **k)

    code, _ = run_giskard(monkeypatch, tmp_path, QuotaCrew(decide=lambda t: make_verdict(False)))

    assert code == 3
    assert "INCOMPLETE" in capsys.readouterr().out
    assert len((tmp_path / "giskard_heldout.jsonl").read_text().splitlines()) == 3

    code, _ = run_giskard(monkeypatch, tmp_path, FakeCrew(decide=lambda t: make_verdict(False)), "--resume")

    assert code == 0
    assert json.loads((tmp_path / "giskard_heldout.json").read_text())["analysed"] == 8
