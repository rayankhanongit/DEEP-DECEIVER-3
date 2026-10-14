import json
import time

from app.security.event_store import SecurityEventStore
from app.security.models import SecurityEvent
from app.security.redaction import redact, safe_excerpt

from security_helpers import FakePersistence, make_monitor


def make_event(outcome="BLOCKED", severity="HIGH", risk=70, category="instruction_override", **kw):
    return SecurityEvent(
        event_type="X",
        severity=severity,
        category=category,
        risk_score=risk,
        confidence=0.9,
        outcome=outcome,
        jailbreak_success=(outcome == "SUCCESS"),
        **kw,
    )


# ---------------- redaction ----------------

def test_api_keys_are_redacted():
    text = "my key is gsk_1234567890abcdefABCDEF and sk-abcdefghijklmnop1234"

    cleaned = redact(text)

    assert "gsk_1234" not in cleaned
    assert "sk-abcdef" not in cleaned
    assert cleaned.count("[REDACTED]") == 2


def test_passwords_tokens_and_bearer_are_redacted():
    cleaned = redact("password=hunter2 and Authorization: Bearer abcdefghijklmnop12345 token: xyz789")

    assert "hunter2" not in cleaned
    assert "abcdefghijklmnop12345" not in cleaned
    assert "xyz789" not in cleaned


def test_emails_are_redacted():
    assert "alice@example.com" not in redact("contact alice@example.com")


def test_excerpt_is_truncated():
    excerpt = safe_excerpt("a" * 5000, max_chars=100)

    assert len(excerpt) == 100
    assert excerpt.endswith("…")


def test_monitor_never_stores_secrets_or_full_prompts():
    persistence = FakePersistence()
    monitor, _ = make_monitor(persistence)

    event = monitor.record(
        category="credential_extraction",
        outcome="BLOCKED",
        risk_score=75,
        severity="HIGH",
        confidence=0.9,
        prompt="Use api_key=gsk_ABCDEFGHIJKLMNOPQRSTUV " + "x" * 3000,
        response="token: supersecretvalue",
    )

    stored = json.dumps(event)

    assert "gsk_ABCDEFGH" not in stored
    assert "supersecretvalue" not in stored
    assert len(event["details"]["prompt_excerpt"]) <= 240


# ---------------- persistence ----------------

def test_events_are_persisted_to_the_backing_store():
    persistence = FakePersistence()
    store = SecurityEventStore(persistence, load_history=False)

    store.add(make_event(), persist_async=False)

    assert len(persistence.written) == 1
    assert persistence.written[0]["category"] == "instruction_override"


def test_history_is_reloaded_from_persistence():
    persistence = FakePersistence()
    first = SecurityEventStore(persistence, load_history=False)

    first.add(make_event(summary="one"), persist_async=False)
    first.add(make_event(summary="two"), persist_async=False)

    restarted = SecurityEventStore(persistence)

    assert [e["summary"] for e in restarted.list()] == ["two", "one"]


def test_persistence_failure_never_breaks_the_store():
    class Broken:
        def write_security_event(self, event):
            raise ConnectionError("influx down")

        def query_security_events(self, limit=0):
            raise ConnectionError("influx down")

    store = SecurityEventStore(Broken())

    store.add(make_event(), persist_async=False)

    assert len(store.list()) == 1


def test_monitor_stores_logs_and_alerts(caplog):
    persistence = FakePersistence()
    monitor, provider = make_monitor(persistence)

    import logging
    logging.getLogger("deep_deceiver.security").propagate = True

    with caplog.at_level(logging.INFO, logger="deep_deceiver.security"):
        event = monitor.record(
            category="instruction_override",
            outcome="SUCCESS",
            risk_score=90,
            severity="CRITICAL",
            confidence=0.9,
            session_id="s1",
        )

    time.sleep(0.1)

    assert event["alert_triggered"] is True
    assert len(provider.sent) == 1
    assert monitor.store.list()[0]["event_id"] == event["event_id"]

    line = next(r.message for r in caplog.records if "SECURITY_EVENT" in r.message)

    assert "severity=CRITICAL" in line
    assert "category=INSTRUCTION_OVERRIDE" in line
    assert "risk=90" in line
    assert "jailbreak_success=true" in line
    assert "alert_triggered=true" in line


# ---------------- dashboard statistics ----------------

def test_stats_are_computed_from_stored_events():
    store = SecurityEventStore()

    store.add(make_event("BLOCKED", "HIGH", 70))
    store.add(make_event("BLOCKED", "MEDIUM", 50))
    store.add(make_event("SUSPICIOUS", "HIGH", 65))
    store.add(make_event("SUCCESS", "CRITICAL", 90))
    store.add(make_event("SAFE", "SAFE", 0))

    stats = store.stats()

    assert stats["total_attempts"] == 4
    assert stats["blocked_attempts"] == 2
    assert stats["successful_jailbreaks"] == 1
    assert stats["suspicious_attempts"] == 1
    assert stats["high_risk_events"] == 3
    assert stats["critical_events"] == 1
    assert stats["average_risk_score"] == 68.8      # (70+50+65+90)/4 = 68.75
    assert stats["model_robustness"] == 50.0
    assert stats["jailbreak_success_rate"] == 25.0
    assert stats["current_threat_level"] == "CRITICAL"
    assert stats["by_category"] == {"instruction_override": 4}


def test_stats_on_empty_store():
    stats = SecurityEventStore().stats()

    assert stats["total_attempts"] == 0
    assert stats["model_robustness"] == 100.0
    assert stats["jailbreak_success_rate"] == 0.0
    assert stats["system_status"] == "PROTECTED"


def test_list_filters_by_severity_and_source():
    store = SecurityEventStore()

    store.add(make_event("BLOCKED", "LOW", 30, source="chat"))
    store.add(make_event("SUCCESS", "CRITICAL", 90, source="red_team"))

    assert len(store.list(min_severity="HIGH")) == 1
    assert store.list(source="chat")[0]["severity"] == "LOW"
    assert store.list(limit=1)[0]["severity"] == "CRITICAL"
