import re

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import demo
from app.services.report import _esc, build_pdf
from app.services.trace import summarize, trace

H = {"X-Operator-Token": "t"}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("OPERATOR_TOKEN", "t")
    demo.reset()
    trace.clear("live")                 # other tests feed the same global trace
    yield TestClient(app)
    demo.reset()


def test_ops_requires_operator(client):
    assert client.get("/ops/sessions").status_code in (401, 403)
    assert client.post("/ops/demo/run").status_code in (401, 403)


def test_demo_run_is_isolated_labelled_and_repeatable(client):
    first = client.post("/ops/demo/run", headers=H).json()
    second = client.post("/ops/demo/run", headers=H).json()

    assert first["origin"] == "demo" and first["session_id"] != second["session_id"]
    assert [t["route"] for t in first["turns"]] == [t["route"] for t in second["turns"]]      # deterministic
    assert all(t["model"] == "demo-replay" and t["event_id"] is None for t in first["turns"])  # no stored event
    assert [t["stage"] for t in first["turns"] if t["stage"]] == [
        "instruction_probing", "privilege_escalation", "data_discovery"]

    live = [s for s in client.get("/ops/sessions", headers=H).json()["sessions"] if s["origin"] == "live"]
    assert live == []                                                                        # live data untouched

    assert client.delete("/ops/demo", headers=H).json()["removed"] == 2
    assert client.get("/ops/sessions", headers=H).json()["sessions"] == []


def test_unknown_session_is_404(client):
    assert client.get("/ops/sessions/nope", headers=H).status_code == 404
    assert client.get("/ops/sessions/nope/report.pdf", headers=H).status_code == 404


def test_latency_separates_origins_and_gates_p95(client):
    client.post("/ops/demo/run", headers=H)
    body = client.get("/ops/latency", headers=H).json()

    assert body["stats"]["live"]["total"]["n"] == 0 and body["stats"]["live"]["total"]["avg"] is None
    assert body["stats"]["demo"]["sensors"]["n"] == 5
    assert body["stats"]["demo"]["sensors"]["p95"] is None          # 5 samples are too few for a p95
    assert summarize([1] * 20)["p95"] == 1
    assert summarize([0, 0])["avg"] == 0                            # zero is a measurement, not 'missing'


def test_report_pdf_is_valid_single_page(client):
    sid = client.post("/ops/demo/run", headers=H).json()["session_id"]
    response = client.get(f"/ops/sessions/{sid}/report.pdf", headers=H)
    pdf = response.content

    assert response.headers["content-type"] == "application/pdf"
    assert re.search(r'filename="incident-[A-Za-z0-9]+-\d{4}-\d{2}-\d{2}\.pdf"', response.headers["content-disposition"])
    assert pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF")
    assert b"/Count 1" in pdf and b"SIMULATED" in pdf

    start = int(re.search(rb"startxref\n(\d+)", pdf).group(1))
    assert pdf[start:start + 4] == b"xref"
    offsets = re.findall(rb"(\d{10}) 00000 n", pdf)
    for number, offset in enumerate(offsets, start=1):               # every xref entry points at its object
        assert pdf[int(offset):].startswith(f"{number} 0 obj".encode())


def test_pdf_escapes_text_and_never_overflows():
    bs = chr(92)
    assert _esc("a(b)" + bs + "c") == "a" + bs + "(b" + bs + ")" + bs + bs + "c"

    session = {"session_id": "s" * 400, "origin": "live", "started": "t", "count": 1, "turns": [{
        "index": 1, "ts": "t", "route": "production", "attack_category": "unknown", "stage": None,
        "completed_stages": [], "risk": 0.1, "severity": "SAFE", "engine": "crewai", "status": "active",
        "event_id": None, "model": None}]}

    assert build_pdf(session, {}).count(b"BT") < 60


def test_report_names_the_real_engine_and_short_timestamps(client):
    sid = client.post("/ops/demo/run", headers=H).json()["session_id"]
    pdf = client.get(f"/ops/sessions/{sid}/report.pdf", headers=H).content

    assert b"Engine: demo-replay" in pdf and b"crewai" not in pdf
    assert b"+00:00" not in pdf
