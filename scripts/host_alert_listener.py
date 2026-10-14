"""
Host alert bridge for Docker deployments.

A container cannot draw a desktop notification on the host. If the backend
is ever run inside Docker, run this tiny listener on the HOST and point the
backend at it:

    # on the host (Windows / macOS / Linux)
    backend\\proj\\Scripts\\python scripts\\host_alert_listener.py

    # in .env for the containerised backend
    SECURITY_WEBHOOK_URL=http://host.docker.internal:8765/alert

The listener binds to 127.0.0.1 only, accepts the same safe-summary payload
the webhook provider sends (no prompts) and shows it through the normal
desktop notification provider.

When the backend runs directly on the host (the default, see
commands.txt) this script is NOT needed.
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "backend"))

from app.security.notifications import DesktopNotificationProvider  # noqa: E402

HOST = os.getenv("HOST_ALERT_BIND", "127.0.0.1")
PORT = int(os.getenv("HOST_ALERT_PORT", "8765"))

provider = DesktopNotificationProvider()


class Handler(BaseHTTPRequestHandler):

    def do_POST(self):
        if self.path != "/alert":
            self.send_error(404)
            return

        try:
            length = min(int(self.headers.get("Content-Length", 0)), 8192)
            payload = json.loads(self.rfile.read(length) or b"{}")

            event = {
                "severity": str(payload.get("severity", "HIGH"))[:16],
                "risk_score": int(payload.get("risk_score", 0)),
                "category": str(payload.get("category", "unknown"))[:64],
                "timestamp": payload.get("timestamp"),
            }

            ok = provider.send(event)

            self.send_response(200 if ok else 502)
            self.end_headers()

        except Exception:
            self.send_error(400)

    def log_message(self, fmt, *args):
        print("[host-alert]", fmt % args)


if __name__ == "__main__":
    print(f"Host alert listener on http://{HOST}:{PORT}/alert")
    HTTPServer((HOST, PORT), Handler).serve_forever()
