"""
Security event store.

Events live in a bounded in-memory window (fast dashboard queries) and are
written through to the application's EXISTING InfluxDB bucket
(measurement `security_events`) so they survive restarts. If InfluxDB is
unreachable the store keeps working from memory and retries after a
cool-down; persistence failures never affect the request that caused them.
"""

import logging
import threading
import time
from collections import deque

from app.security.models import SecurityEvent, severity_rank


logger = logging.getLogger("deep_deceiver.security.store")

PERSIST_RETRY_SECONDS = 30
MEMORY_WINDOW = 2000


class SecurityEventStore:

    def __init__(self, persistence=None, load_history: bool = True):
        """
        persistence: object with write_security_event(dict) and
                     query_security_events(limit) - normally InfluxDBService.
        """
        self._events: deque[dict] = deque(maxlen=MEMORY_WINDOW)
        self._lock = threading.Lock()
        self._persistence = persistence
        self._persist_disabled_until = 0.0
        self._known_ids: set[str] = set()

        if persistence is not None and load_history:
            self._load_history()

    # --------------------------------------------------

    def _load_history(self):
        try:
            history = self._persistence.query_security_events(limit=MEMORY_WINDOW)

            # query returns newest first; store oldest first.
            for event in reversed(history):
                self._events.append(event)
                self._known_ids.add(event["event_id"])

        except Exception as error:
            logger.warning("Could not load security history: %s", error)
            self._persist_disabled_until = time.time() + PERSIST_RETRY_SECONDS

    def _persist(self, event: dict):
        if self._persistence is None:
            return

        if time.time() < self._persist_disabled_until:
            return

        try:
            self._persistence.write_security_event(event)

        except Exception as error:
            logger.warning("Security event persistence failed: %s", error)
            self._persist_disabled_until = time.time() + PERSIST_RETRY_SECONDS

    # --------------------------------------------------

    def add(self, event: SecurityEvent | dict, persist_async: bool = True) -> dict:
        data = event.to_dict() if isinstance(event, SecurityEvent) else dict(event)

        with self._lock:
            self._events.append(data)
            self._known_ids.add(data["event_id"])

        if persist_async and self._persistence is not None:
            threading.Thread(
                target=self._persist,
                args=(data,),
                daemon=True,
            ).start()
        else:
            self._persist(data)

        return data

    def update(self, event_id: str, **changes) -> dict | None:
        """Update an in-memory event (e.g. alert_triggered) after creation."""

        with self._lock:
            for event in self._events:
                if event["event_id"] == event_id:
                    event.update(changes)
                    return event

        return None

    def list(
        self,
        limit: int = 100,
        min_severity: str | None = None,
        source: str | None = None,
        assessment_id: str | None = None,
    ) -> list[dict]:
        with self._lock:
            events = list(self._events)

        events.reverse()  # newest first

        if min_severity:
            floor = severity_rank(min_severity)
            events = [e for e in events if severity_rank(e["severity"]) >= floor]

        if source:
            events = [e for e in events if e.get("source") == source]

        if assessment_id:
            events = [e for e in events if e.get("assessment_id") == assessment_id]

        return events[:limit]

    def clear(self):
        with self._lock:
            self._events.clear()
            self._known_ids.clear()

    # --------------------------------------------------
    # Statistics (always computed from stored events)
    # --------------------------------------------------

    def stats(self, source: str | None = None) -> dict:
        events = self.list(limit=MEMORY_WINDOW, source=source)

        attacks = [e for e in events if e["outcome"] != "SAFE"]

        total_attempts = len(attacks)
        successes = [e for e in attacks if e["outcome"] == "SUCCESS"]
        blocked = [e for e in attacks if e["outcome"] == "BLOCKED"]
        suspicious = [e for e in attacks if e["outcome"] == "SUSPICIOUS"]

        high = [e for e in attacks if severity_rank(e["severity"]) >= severity_rank("HIGH")]
        critical = [e for e in attacks if e["severity"] == "CRITICAL"]

        scores = [e["risk_score"] for e in attacks]

        average_risk = round(sum(scores) / len(scores), 1) if scores else 0.0

        # "Resolved" attempts are those whose outcome is known.
        resolved = len(successes) + len(blocked) + len(suspicious)

        robustness = (
            round(100 * len(blocked) / resolved, 1) if resolved else 100.0
        )

        success_rate = (
            round(100 * len(successes) / resolved, 1) if resolved else 0.0
        )

        by_category: dict[str, int] = {}
        for e in attacks:
            by_category[e["category"]] = by_category.get(e["category"], 0) + 1

        # Current threat level: the worst severity in the last 15 minutes.
        recent_cutoff = time.time() - 15 * 60
        recent_levels = []
        for e in attacks:
            try:
                from datetime import datetime
                ts = datetime.fromisoformat(e["timestamp"]).timestamp()
            except Exception:
                continue
            if ts >= recent_cutoff:
                recent_levels.append(e["severity"])

        threat_level = "LOW"
        if recent_levels:
            threat_level = max(recent_levels, key=severity_rank)

        contained = [e for e in attacks if e.get("details", {}).get("contained")]

        return {
            "honeypot_interactions": len(contained),
            "honeypot_sessions": len({e.get("session_id") for e in contained}),
            "total_attempts": total_attempts,
            "blocked_attempts": len(blocked),
            "suspicious_attempts": len(suspicious),
            "successful_jailbreaks": len(successes),
            "high_risk_events": len(high),
            "critical_events": len(critical),
            "alerts_triggered": sum(1 for e in attacks if e.get("alert_triggered")),
            "average_risk_score": average_risk,
            "model_robustness": robustness,
            "jailbreak_success_rate": success_rate,
            "current_threat_level": threat_level,
            "by_category": by_category,
            "system_status": "PROTECTED" if not critical else "UNDER ATTACK",
        }
