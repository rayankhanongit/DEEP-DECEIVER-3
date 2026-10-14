"""
Alert engine and real-time broadcaster.

AlertEngine decides whether a security event deserves an alert, delivers
it through the notification abstraction (host computer) and publishes it
to connected dashboards (Server-Sent Events).
"""

import logging
import queue
import threading
import time

from app.security.config import get_settings
from app.security.notifications import NotificationService, notification_service


logger = logging.getLogger("deep_deceiver.security.alerts")


class AlertBroadcaster:
    """Thread-safe fan-out of events to SSE subscribers."""

    def __init__(self):
        self._subscribers: set[queue.Queue] = set()
        self._lock = threading.Lock()
        self.closed = False

    def close(self):
        """Called on application shutdown so open SSE streams can end."""
        self.closed = True

    def subscribe(self) -> queue.Queue:
        subscriber: queue.Queue = queue.Queue(maxsize=100)

        with self._lock:
            self._subscribers.add(subscriber)

        return subscriber

    def unsubscribe(self, subscriber: queue.Queue):
        with self._lock:
            self._subscribers.discard(subscriber)

    def publish(self, payload: dict):
        with self._lock:
            subscribers = list(self._subscribers)

        for subscriber in subscribers:
            try:
                subscriber.put_nowait(payload)
            except queue.Full:
                pass  # slow client: drop rather than block the pipeline

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)


class AlertEngine:

    def __init__(
        self,
        notifier: NotificationService | None = None,
        broadcaster: AlertBroadcaster | None = None,
    ):
        self.notifier = notifier or notification_service
        self.broadcaster = broadcaster or AlertBroadcaster()
        self._last_alert: dict[tuple, float] = {}
        self._lock = threading.Lock()

    def should_alert(self, event: dict) -> bool:
        settings = get_settings()

        if event["outcome"] == "SAFE":
            return False

        # A confirmed boundary violation is always worth an alert.
        if event["outcome"] == "SUCCESS" and event["risk_score"] >= settings.alert_threshold:
            return True

        return event["risk_score"] >= settings.alert_threshold

    def _in_cooldown(self, event: dict) -> bool:
        settings = get_settings()

        key = (
            event.get("session_id") or event.get("assessment_id"),
            event.get("category"),
            event.get("outcome"),
        )

        now = time.time()

        with self._lock:
            last = self._last_alert.get(key, 0.0)

            if now - last < settings.alert_cooldown_seconds:
                return True

            self._last_alert[key] = now

        return False

    def handle(self, event: dict) -> bool:
        """
        Evaluate an event and, if warranted, alert. Returns True when an
        alert was issued. Never raises.
        """

        try:
            if not self.should_alert(event):
                return False

            settings = get_settings()

            # Frontend dashboards always get the alert...
            self.broadcaster.publish({
                "type": "security_alert",
                "event": event,
                "critical": event["risk_score"] >= settings.critical_threshold,
            })

            # ...the host computer is rate-limited to avoid toast storms.
            if not self._in_cooldown(event):
                self.notifier.send_security_alert(event)

            return True

        except Exception as error:
            logger.warning("Alert handling failed: %s", error)
            return False


alert_engine = AlertEngine()
