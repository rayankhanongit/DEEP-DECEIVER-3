import { useCallback, useEffect, useId, useRef, useState } from "react";
import { ChevronRight, CircleAlert, Play, RotateCcw, Square } from "lucide-react";

import { getJSON, postJSON, prettyCategory } from "../api";
import Button from "./ui/Button";
import Dialog from "./ui/Dialog";
import { Badge, SeverityBadge, StatusBadge } from "./ui/Badge";
import { CountUp, RiskMeter, Spinner } from "./ui/Display";

const MODE_LABEL = {
  quick: "Quick scan",
  standard: "Standard",
  deep: "Deep assessment",
};

const FINDING_STATE = {
  BLOCKED: "blocked",
  SUSPICIOUS: "warning",
  SUCCESSFUL: "jailbreak",
  ERROR: "warning",
};

function Finding({ finding }) {
  const [open, setOpen] = useState(false);
  const bodyId = useId();

  return (
    <li className={`finding finding-${finding.status}`}>
      <h4>
        <button
          type="button"
          className="finding-head"
          aria-expanded={open}
          aria-controls={bodyId}
          onClick={() => setOpen(!open)}
        >
          <ChevronRight size={16} className="chev" aria-hidden="true" />
          <span className="finding-title">
            <span className="num">{finding.index}.</span> {prettyCategory(finding.category)}
          </span>
          <SeverityBadge level={finding.severity} />
          <span className="num finding-conf">{Math.round(finding.confidence * 100)}%</span>
          <StatusBadge
            state={FINDING_STATE[finding.status] || "warning"}
            label={
              finding.status === "SUCCESSFUL"
                ? "Successful"
                : finding.status === "BLOCKED"
                ? "Blocked"
                : finding.status === "SUSPICIOUS"
                ? "Suspicious"
                : "Error"
            }
          />
        </button>
      </h4>

      {open && (
        <div id={bodyId} className="finding-body">
          <dl className="kv">
            <dt>Objective</dt>
            <dd>{finding.objective}</dd>

            <dt>Expected behaviour</dt>
            <dd>{finding.expected_behavior}</dd>

            <dt>Evaluation</dt>
            <dd>
              {finding.classification} · risk <span className="num">{finding.risk_score}/100</span>
              {finding.judge_used ? " · AI-judged" : ""}
            </dd>

            <dt>Reason</dt>
            <dd>{finding.reason}</dd>

            {finding.violated_boundary && (
              <>
                <dt>Violated boundary</dt>
                <dd>{finding.violated_boundary}</dd>
              </>
            )}

            <dt>Test prompt (redacted)</dt>
            <dd className="quote">{finding.prompt_excerpt}</dd>

            <dt>Model response (redacted)</dt>
            <dd className="quote">{finding.response_excerpt || "—"}</dd>

            <dt>Escalation</dt>
            <dd>
              Level <span className="num">{finding.level + 1}</span>
              {finding.turns > 1 ? ` · ${finding.turns} turns` : ""}
              {finding.alert_triggered ? " · alert raised" : ""}
            </dd>
          </dl>
        </div>
      )}
    </li>
  );
}

function RedTeamPanel({ onClose }) {
  const [config, setConfig] = useState(null);
  const [mode, setMode] = useState("standard");
  const [selected, setSelected] = useState([]);
  const [error, setError] = useState("");

  const [assessmentId, setAssessmentId] = useState(null);
  const [view, setView] = useState(null);

  const pollRef = useRef(null);

  useEffect(() => {
    getJSON("/red-team/config")
      .then((data) => {
        setConfig(data);
        setSelected(data.categories.map((c) => c.id));
      })
      .catch(() => setError("Unable to reach the backend."));
  }, []);

  const poll = useCallback(async (id) => {
    try {
      const data = await getJSON(`/red-team/${id}`);

      setView(data);

      if (data.status !== "running") {
        clearInterval(pollRef.current);
      }
    } catch {
      clearInterval(pollRef.current);
      setError("Lost connection to the assessment.");
    }
  }, []);

  useEffect(() => () => clearInterval(pollRef.current), []);

  const start = async () => {
    setError("");

    try {
      const data = await postJSON("/red-team/start", {
        mode,
        categories: selected,
      });

      setAssessmentId(data.assessment_id);
      setView(null);

      clearInterval(pollRef.current);
      poll(data.assessment_id);
      pollRef.current = setInterval(() => poll(data.assessment_id), 1000);
    } catch (err) {
      setError(err.message);
    }
  };

  const stop = async () => {
    try {
      await postJSON(`/red-team/${assessmentId}/stop`);
    } catch (err) {
      setError(err.message);
    }
  };

  const reset = () => {
    clearInterval(pollRef.current);
    setAssessmentId(null);
    setView(null);
    setError("");
  };

  const toggle = (id) =>
    setSelected((prev) => (prev.includes(id) ? prev.filter((c) => c !== id) : [...prev, id]));

  const running = view?.status === "running";
  const finished = view && view.status !== "running";
  const report = view?.report;

  const title = finished ? "Assessment complete" : "Red Team assessment";

  return (
    <Dialog
      title={title}
      description="Adaptive adversarial testing of this application’s own model. Nothing leaves the app."
      onClose={onClose}
      variant="sheet"
    >
      {error && (
        <div className="form-error" role="alert">
          <CircleAlert size={16} aria-hidden="true" />
          {error}
        </div>
      )}

      {/* ---------------- configuration ---------------- */}

      {!assessmentId && config && (
        <>
          <section className="rt-section">
            <h3>Target</h3>
            <p className="rt-target">Current AI model · DEEP-DECEIVER protected LLM</p>
          </section>

          <fieldset className="rt-section">
            <legend>Assessment mode</legend>

            <div className="segmented">
              {config.modes.map((m) => (
                <label key={m.id} className={mode === m.id ? "seg active" : "seg"}>
                  <input
                    type="radio"
                    name="mode"
                    value={m.id}
                    checked={mode === m.id}
                    onChange={() => setMode(m.id)}
                  />
                  <strong>{MODE_LABEL[m.id] || m.id}</strong>
                  <span className="num">{m.tests} tests</span>
                </label>
              ))}
            </div>
          </fieldset>

          <fieldset className="rt-section">
            <legend>Attack categories</legend>

            <div className="check-grid">
              {config.categories.map((c) => (
                <label key={c.id} className="check" title={c.description}>
                  <input
                    type="checkbox"
                    checked={selected.includes(c.id)}
                    onChange={() => toggle(c.id)}
                  />
                  <span>{c.label}</span>
                </label>
              ))}
            </div>
          </fieldset>

          {!config.enabled && (
            <div className="form-error" role="alert">
              <CircleAlert size={16} aria-hidden="true" />
              Red Team is disabled (RED_TEAM_ENABLED=false).
            </div>
          )}

          <div className="dialog-actions">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>

            <Button
              variant="primary"
              icon={Play}
              onClick={start}
              disabled={selected.length === 0 || !config.enabled}
              data-autofocus
            >
              Start assessment
            </Button>
          </div>
        </>
      )}

      {!assessmentId && !config && !error && (
        <div className="empty" role="status">
          <Spinner label="Loading configuration" />
        </div>
      )}

      {/* ---------------- progress / results ---------------- */}

      {assessmentId && (
        <>
          {!view && (
            <div className="empty" role="status">
              <Spinner label="Starting assessment" />
              <p>Starting assessment…</p>
            </div>
          )}

          {running && (
            <div className="rt-progress">
              <div className="rt-progress-head">
                <span role="status">
                  <Spinner label="Running" /> Running {MODE_LABEL[view.mode]?.toLowerCase()} · test{" "}
                  <span className="num">
                    {view.progress.executed} of {view.progress.planned}
                  </span>
                </span>

                <Button variant="secondary" size="sm" icon={Square} onClick={stop}>
                  Stop
                </Button>
              </div>

              <div
                className="bar"
                role="progressbar"
                aria-valuemin={0}
                aria-valuemax={view.progress.planned}
                aria-valuenow={view.progress.executed}
                aria-label="Assessment progress"
              >
                <div
                  className="bar-fill"
                  style={{ transform: `scaleX(${view.progress.executed / view.progress.planned})` }}
                />
              </div>
            </div>
          )}

          {finished && report && (
            <>
              {view.status === "failed" && (
                <div className="form-error" role="alert">
                  <CircleAlert size={16} aria-hidden="true" />
                  The assessment failed ({view.error}). Partial results are shown below.
                </div>
              )}

              <div className="rt-summary">
                <RiskMeter value={report.overall_risk_score} level={report.overall_risk} size={190} />

                <div className="rt-stats">
                  <div className="rt-stat">
                    <span>Tests run</span>
                    <strong className="num">{report.tests_executed}</strong>
                  </div>
                  <div className="rt-stat rt-ok">
                    <span>Blocked</span>
                    <strong className="num">{report.blocked}</strong>
                  </div>
                  <div className="rt-stat rt-warn">
                    <span>Suspicious</span>
                    <strong className="num">{report.suspicious}</strong>
                  </div>
                  <div className="rt-stat rt-crit">
                    <span>Successful</span>
                    <strong className="num">{report.successful}</strong>
                  </div>
                  <div className="rt-stat rt-wide">
                    <span>Model robustness</span>
                    <strong className="num">
                      <CountUp value={report.model_robustness} suffix="%" decimals={0} />
                    </strong>
                  </div>
                </div>
              </div>

              <p className="rt-note">
                {report.stop_reason === "stopped_by_user" && "Stopped by user · "}
                {report.stop_reason === "timeout" && "Stopped at the time limit · "}
                {report.stop_reason === "critical_finding" && "Stopped after a critical finding · "}
                {report.alerts_triggered > 0 && `${report.alerts_triggered} host alert(s) raised · `}
                Duration <span className="num">{report.duration_seconds ?? "—"}s</span>
              </p>
            </>
          )}

          {view && view.findings.length > 0 && (
            <section className="rt-section">
              <h3>
                Findings <Badge>{view.findings.length}</Badge>
              </h3>

              <ol className="findings">
                {view.findings.map((finding) => (
                  <Finding key={finding.index} finding={finding} />
                ))}
              </ol>
            </section>
          )}

          {finished && (
            <div className="dialog-actions">
              <Button variant="secondary" icon={RotateCcw} onClick={reset}>
                New assessment
              </Button>

              <Button variant="primary" onClick={onClose} data-autofocus>
                Close
              </Button>
            </div>
          )}
        </>
      )}
    </Dialog>
  );
}

export default RedTeamPanel;
