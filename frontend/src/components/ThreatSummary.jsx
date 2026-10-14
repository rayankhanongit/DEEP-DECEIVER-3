function ThreatSummary({ stats }) {
  return (
    <div className="summary-grid">

      <div className="summary-card">
        <div className="summary-label">
          Total Events
        </div>
        <div className="summary-value">
          {stats.total_events}
        </div>
      </div>

      <div className="summary-card threat-card">
        <div className="summary-label">
          Threats Detected
        </div>
        <div className="summary-value">
          {stats.threats_detected}
        </div>
      </div>

      <div className="summary-card honeypot-card">
        <div className="summary-label">
          Honeypots Activated
        </div>
        <div className="summary-value">
          {stats.honeypot_activations}
        </div>
      </div>

      <div className="summary-card">
        <div className="summary-label">
          Average Risk
        </div>
        <div className="summary-value">
          {(stats.average_risk_score * 100).toFixed(1)}%
        </div>
      </div>

    </div>
  );
}

export default ThreatSummary;