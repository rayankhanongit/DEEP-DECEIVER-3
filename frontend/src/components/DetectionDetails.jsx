function Row({ label, children, tone }) {
  return (
    <div className="detection-row">
      <span>{label}</span>
      <span className={tone}>{children}</span>
    </div>
  );
}

const num = (value, digits = 2) =>
  typeof value === "number" ? value.toFixed(digits) : "—";

/**
 * The original detection-pipeline panel (Fast Filter, Sentry, Analyst,
 * Orchestrator, Decoy), unchanged in content, now collapsible.
 */
function DetectionDetails({ msg }) {
  const d = msg.detection;

  return (
    <div className="detection-panel">
      <div className="response-source-section">
        <div className="detection-title">Response Source</div>

        <div
          className={
            msg.responseSource === "decoy" ? "source-shadow" : "source-production"
          }
        >
          {msg.responseSource === "decoy"
            ? "SHADOW / HONEYPOT"
            : "PRODUCTION LLM"}
        </div>
      </div>

      {msg.session && (
        <div
          className={
            msg.session.environment === "shadow"
              ? "session-status session-contained"
              : "session-status session-active"
          }
        >
          <div className="detection-title">Session Status</div>

          <Row
            label="Status"
            tone={
              msg.session.status === "contained"
                ? "detection-danger"
                : "detection-safe"
            }
          >
            {msg.session.status === "contained" ? "CONTAINED" : "ACTIVE"}
          </Row>

          <Row label="Environment">
            {msg.session.environment.toUpperCase()}
          </Row>

          <Row
            label="Production Access"
            tone={
              msg.session.production_access
                ? "detection-safe"
                : "detection-danger"
            }
          >
            {msg.session.production_access ? "TRUE" : "FALSE"}
          </Row>
        </div>
      )}

      <div className="detection-section">
        <div className="detection-subtitle">Fast Filter</div>

        <Row
          label="Status"
          tone={d.fast_filter.flagged ? "detection-danger" : "detection-safe"}
        >
          {d.fast_filter.flagged ? "Suspicious" : "Benign"}
        </Row>

        <Row label="Score">{num(d.fast_filter.score)}</Row>
      </div>

      <div className="detection-section">
        <div className="detection-subtitle">Sentry</div>

        <Row
          label="Status"
          tone={d.sentry.flagged ? "detection-danger" : "detection-safe"}
        >
          {d.sentry.flagged ? "Threat Detected" : "No Threat"}
        </Row>

        <Row label="Semantic Score">{num(d.sentry.score, 4)}</Row>
        <Row label="Threshold">{num(d.sentry.threshold)}</Row>
      </div>

      <div className="detection-section">
        <div className="detection-subtitle">Analyst</div>

        <Row label="Intent">{d.analyst.intent}</Row>
        <Row label="Attack Category">{d.analyst.attack_category}</Row>
        <Row label="Attacker Goal">{d.analyst.attacker_goal}</Row>
        <Row label="Risk Score">{num(d.analyst.risk_score, 4)}</Row>
      </div>

      <div className="detection-section">
        <div className="detection-subtitle">Orchestrator</div>

        <Row
          label="Route"
          tone={
            d.orchestrator.route === "shadow"
              ? "detection-danger"
              : "detection-safe"
          }
        >
          {d.orchestrator.route.toUpperCase()}
        </Row>

        <Row label="Action">{d.orchestrator.action}</Row>
        <Row label="Final Risk">{num(d.orchestrator.final_risk_score, 4)}</Row>
        <Row label="Threshold">{num(d.orchestrator.threshold)}</Row>

        <Row
          label="Decision Reason"
          tone={
            d.orchestrator.decision_reason === "sentry_threat"
              ? "detection-danger"
              : "detection-safe"
          }
        >
          {d.orchestrator.decision_reason?.replace(/_/g, " ").toUpperCase()}
        </Row>
      </div>

      {msg.decoy && (
        <div className="decoy-panel">
          <div className="detection-title">Decoy Agent</div>

          <Row label="Environment">{msg.decoy.environment}</Row>
          <Row label="Response Type">{msg.decoy.response_type}</Row>

          <Row label="Production Access" tone="detection-safe">
            {msg.decoy.production_access ? "TRUE" : "FALSE"}
          </Row>
        </div>
      )}
    </div>
  );
}

export default DetectionDetails;
