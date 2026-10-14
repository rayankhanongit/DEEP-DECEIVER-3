import { useEffect } from "react";
import { ShieldX, TriangleAlert, X } from "lucide-react";

import { formatTime, prettyCategory } from "../api";
import Button from "./ui/Button";
import { SeverityBadge } from "./ui/Badge";

function SecurityToast({ alert, onClose, onView }) {
  useEffect(() => {
    if (!alert) return undefined;

    const timer = setTimeout(onClose, 14000);

    return () => clearTimeout(timer);
  }, [alert, onClose]);

  if (!alert) return null;

  const event = alert.event;
  const Icon = event.jailbreak_success ? ShieldX : TriangleAlert;

  return (
    <div className={`toast ${alert.critical ? "toast-crit" : "toast-warn"}`} role="alert">
      <div className="toast-head">
        <Icon size={18} aria-hidden="true" />
        <strong>
          {event.jailbreak_success ? "Successful jailbreak" : "Jailbreak attempt detected"}
          {alert.test ? " (test)" : ""}
        </strong>

        <button
          type="button"
          className="btn btn-ghost btn-icon toast-close"
          onClick={onClose}
          aria-label="Dismiss alert"
        >
          <X size={16} aria-hidden="true" />
        </button>
      </div>

      <div className="toast-meta">
        <SeverityBadge level={event.severity} />
        <span className="num">Risk {event.risk_score}/100</span>
        <span>{prettyCategory(event.category)}</span>
        <span className="num">{formatTime(event.timestamp)}</span>
      </div>

      <Button variant="secondary" size="sm" onClick={onView}>
        View security event
      </Button>
    </div>
  );
}

export default SecurityToast;
