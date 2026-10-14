"""
Notification abstraction.

The application only ever calls

    notification_service.send_security_alert(event)

and the configured providers decide how the alert is delivered. A provider
failure is logged and swallowed: notifications must never crash the app.

Providers
---------
DesktopNotificationProvider   native OS notification on the machine the
                              backend process runs on (Windows balloon/toast
                              via PowerShell - no extra dependency)
ConsoleNotificationProvider   structured log line
WebhookNotificationProvider   HTTP POST - used as the host bridge when the
                              backend runs inside Docker (see
                              scripts/host_alert_listener.py)

Alerts only ever contain a SAFE SUMMARY (severity, score, category, time).
The prompt text stays in the dashboard / event store.
"""

import json
import logging
import os
import platform
import subprocess
import sys
import urllib.request
from abc import ABC, abstractmethod
from datetime import datetime

from app.security.config import get_settings


logger = logging.getLogger("deep_deceiver.security.notify")


def build_alert_text(event: dict) -> tuple[str, str]:
    """Safe, short title/body for an alert. Never includes prompts."""

    category = str(event.get("category", "unknown")).replace("_", " ").title()

    if event.get("jailbreak_success"):
        threat = "Successful jailbreak"
    else:
        threat = "Potential jailbreak attempt"

    try:
        stamp = datetime.fromisoformat(event["timestamp"]).astimezone().strftime("%H:%M:%S")
    except Exception:
        stamp = datetime.now().strftime("%H:%M:%S")

    title = "DEEP-DECEIVER SECURITY ALERT"

    body = (
        f"{threat}\n"
        f"Severity: {event.get('severity', 'HIGH')}  |  "
        f"Risk: {event.get('risk_score', 0)}/100\n"
        f"Category: {category}\n"
        f"Time: {stamp}"
    )

    return title, body


class NotificationProvider(ABC):
    name = "base"

    @abstractmethod
    def send(self, event: dict) -> bool:
        """Deliver the alert. Return True if it was handed off."""


class ConsoleNotificationProvider(NotificationProvider):
    name = "console"

    def send(self, event: dict) -> bool:
        title, body = build_alert_text(event)
        logger.warning("%s | %s", title, body.replace("\n", " | "))
        return True


_WINDOWS_SCRIPT = r"""
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$n = New-Object System.Windows.Forms.NotifyIcon
$n.Icon = [System.Drawing.SystemIcons]::Warning
$n.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
$n.BalloonTipTitle = $env:DD_ALERT_TITLE
$n.BalloonTipText = $env:DD_ALERT_BODY
$n.Visible = $true
$n.ShowBalloonTip(10000)
Start-Sleep -Seconds 11
$n.Dispose()
"""


class DesktopNotificationProvider(NotificationProvider):
    name = "desktop"

    def send(self, event: dict) -> bool:
        title, body = build_alert_text(event)

        system = platform.system()

        try:
            if system == "Windows":
                env = {
                    **os.environ,
                    "DD_ALERT_TITLE": title,
                    "DD_ALERT_BODY": body,
                }

                creation = 0

                if hasattr(subprocess, "CREATE_NO_WINDOW"):
                    creation = subprocess.CREATE_NO_WINDOW

                # Detached: the balloon lives for ~11 s without blocking
                # the request that triggered it. Text goes through
                # environment variables so it is never parsed as code.
                subprocess.Popen(
                    [
                        "powershell",
                        "-NoProfile",
                        "-NonInteractive",
                        "-ExecutionPolicy", "Bypass",
                        "-Command", _WINDOWS_SCRIPT,
                    ],
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=creation,
                )
                return True

            if system == "Darwin":
                subprocess.Popen(
                    [
                        "osascript",
                        "-e",
                        "on run argv\n"
                        "display notification (item 2 of argv) "
                        "with title (item 1 of argv)\n"
                        "end run",
                        title,
                        body.replace("\n", " - "),
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return True

            subprocess.Popen(
                ["notify-send", "-u", "critical", title, body],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True

        except Exception as error:
            logger.warning("Desktop notification failed: %s", error)
            return False


class WebhookNotificationProvider(NotificationProvider):
    name = "webhook"

    def __init__(self, url: str, timeout: float = 3.0):
        self.url = url
        self.timeout = timeout

    def send(self, event: dict) -> bool:
        if not self.url:
            return False

        title, body = build_alert_text(event)

        payload = json.dumps({
            "title": title,
            "body": body,
            "severity": event.get("severity"),
            "risk_score": event.get("risk_score"),
            "category": event.get("category"),
            "timestamp": event.get("timestamp"),
        }).encode("utf-8")

        try:
            request = urllib.request.Request(
                self.url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            with urllib.request.urlopen(request, timeout=self.timeout):
                pass

            return True

        except Exception as error:
            logger.warning("Webhook notification failed: %s", error)
            return False


class NotificationService:

    def __init__(self, providers: list[NotificationProvider] | None = None):
        self._providers = providers

    @property
    def providers(self) -> list[NotificationProvider]:
        if self._providers is not None:
            return self._providers

        settings = get_settings()

        providers: list[NotificationProvider] = [
            ConsoleNotificationProvider()
        ]

        if settings.desktop_notifications:
            providers.append(DesktopNotificationProvider())

        if settings.webhook_url:
            providers.append(WebhookNotificationProvider(settings.webhook_url))

        return providers

    def send_security_alert(self, event: dict) -> dict:
        """
        Fan out to every provider. Returns {provider_name: delivered}.
        Never raises.
        """

        results = {}

        for provider in self.providers:
            try:
                results[provider.name] = bool(provider.send(event))
            except Exception as error:
                logger.warning(
                    "Notification provider %s crashed: %s",
                    provider.name,
                    error,
                )
                results[provider.name] = False

        return results


notification_service = NotificationService()
