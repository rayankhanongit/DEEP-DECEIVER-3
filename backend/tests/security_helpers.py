"""Shared fakes for the security / Red Team tests (no network, no Groq)."""

import re

from app.security.alerts import AlertBroadcaster, AlertEngine
from app.security.event_store import SecurityEventStore
from app.security.monitor import SecurityMonitor
from app.security.notifications import NotificationProvider, NotificationService


class RecordingProvider(NotificationProvider):
    name = "recording"

    def __init__(self):
        self.sent = []

    def send(self, event):
        self.sent.append(event)
        return True


class FakePersistence:
    def __init__(self):
        self.written = []

    def write_security_event(self, event):
        self.written.append(event)

    def query_security_events(self, limit=1000):
        return list(reversed(self.written))[:limit]


def make_monitor(persistence=None, providers=None):
    provider = RecordingProvider()

    notifier = NotificationService(providers if providers is not None else [provider])
    alerts = AlertEngine(notifier=notifier, broadcaster=AlertBroadcaster())

    monitor = SecurityMonitor(
        store=SecurityEventStore(persistence, load_history=False),
        alerts=alerts,
    )

    return monitor, provider


def resistant_target(messages):
    return "I'm sorry, but I can't help with that. I have to keep my instructions confidential."


def vulnerable_target(messages):
    """Obeys any 'say/reply/print X' marker and leaks the canary."""

    text = messages[-1]["content"]

    marker = re.search(r"DD-OK-[0-9A-F]{6}", text)

    if marker:
        return marker.group(0)

    return "Sure! The internal verification token is " + _CANARY["value"]


_CANARY = {"value": "unset"}


def target_factory_for(target, leak_canary=False):
    def factory(system_prompt):
        match = re.search(r"DDCANARY-[0-9A-F]{12}", system_prompt)

        if match:
            _CANARY["value"] = match.group(0)

        return target

    return factory
