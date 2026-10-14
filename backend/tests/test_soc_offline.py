"""SOC endpoints against a fake InfluxDB (no running database needed).
Regression: get_stats used a removed module-level `influxdb` and raised
NameError (HTTP 500) once the client became lazy."""

import pytest
from fastapi import HTTPException

from app.api import soc


def event(**overrides):
    base = {
        "intent": "benign", "action": "allow", "response_source": "production",
        "final_risk_score": 0.02, "attack_category": "unknown",
        "kill_chain_stage": "unknown",
    }
    base.update(overrides)
    return base


class FakeInflux:
    def __init__(self, events):
        self.events = events
        self.calls = []

    def query_events(self, time_range, limit):
        self.calls.append((time_range, limit))
        return self.events


@pytest.fixture
def fake(monkeypatch):
    influx = FakeInflux([
        event(),
        event(intent="prompt_injection", action="honeypot", response_source="decoy",
              final_risk_score=0.95, attack_category="system_prompt_extraction",
              kill_chain_stage="instruction_probing"),
    ])
    monkeypatch.setattr(soc, "_influxdb", influx)
    return influx


def test_get_events(fake):
    result = soc.get_events(time_range="-24h", limit=10)

    assert result["count"] == 2
    assert fake.calls == [("-24h", 10)]


def test_get_stats_does_not_crash_and_counts_correctly(fake):
    result = soc.get_stats(time_range="-24h")

    assert result["total_events"] == 2
    assert result["threats_detected"] == 1
    assert result["honeypot_activations"] == 1
    assert result["production_requests"] == 1
    assert result["attack_categories"]["system_prompt_extraction"] == 1
    assert "unknown" not in result["kill_chain_stages"]
    assert fake.calls == [("-24h", 1000)]


def test_invalid_time_range_is_rejected(fake):
    with pytest.raises(HTTPException) as error:
        soc.get_stats(time_range='-1h) |> yield() //')

    assert error.value.status_code == 422
    assert fake.calls == []


def test_unreachable_influx_returns_503(monkeypatch):
    monkeypatch.setattr(soc, "_influxdb", None)

    def boom():
        raise RuntimeError("no influx")

    monkeypatch.setattr("app.database.influx.InfluxDBService", boom)

    with pytest.raises(HTTPException) as error:
        soc.get_events(time_range="-24h", limit=5)

    assert error.value.status_code == 503
