import { useEffect, useState } from "react";

import { API, getOperatorToken } from "../api";

/**
 * Subscribes to the backend's Server-Sent Events stream and exposes the
 * most recent HIGH / CRITICAL alert. EventSource reconnects automatically.
 */
export default function useSecurityStream(enabled) {
  const [alert, setAlert] = useState(null);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    if (!enabled) return undefined;

    let source;

    try {
      source = new EventSource(
        `${API}/security/stream?token=${encodeURIComponent(getOperatorToken())}`
      );
    } catch {
      return undefined;
    }

    source.onopen = () => setConnected(true);
    source.onerror = () => setConnected(false);

    source.onmessage = (message) => {
      try {
        const payload = JSON.parse(message.data);

        if (payload.type === "security_alert") {
          setAlert({ ...payload, receivedAt: Date.now() });
        }
      } catch {
        /* ignore malformed frames */
      }
    };

    return () => source.close();
  }, [enabled]);

  return { alert, connected, clearAlert: () => setAlert(null) };
}
