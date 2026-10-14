import { useCallback, useEffect, useId, useState } from "react";
import {
  BellRing,
  ChevronRight,
  CircleAlert,
  Ghost,
  RefreshCw,
  ShieldCheck,
  ShieldX,
  Target,
} from "lucide-react";

import { formatTime, getJSON, postJSON, prettyCategory } from "../api";
import Button from "../components/ui/Button";
import { Badge, SeverityBadge, StatusBadge } from "../components/ui/Badge";
import { EmptyState, MetricCard, RiskMeter, Spinner } from "../components/ui/Display";
import { stateFor } from "../components/ui/status";

function levelFor(score) {
  if (score > 80) return "CRITICAL";
  if (score > 60) return "HIGH";
  if (score > 40) return "MEDIUM";
  if (score > 20) return "LOW";
  return "SAFE";
}

/** One plain sentence that answers "how are we doing?". */
function verdictFor(stats) {
  if (stats.total_attempts === 0) {
    return {
      title: "No attacks recorded",
      text: "The model has not faced any attempts yet. Send one from the chat, or run a Red Team assessment.",
    };
  }

  if (stats.successful_jailbreaks > 0) {
    return {
      title: `${stats.successful_jailbreaks} jailbreak${stats.successful_jailbreaks === 1 ? "" : "s"} got through`,
      text: `The model resisted ${stats.model_robustness}% of attempts. Review the successful findings below.`,
    };
  }

  return {
    title: "Every attempt was stopped",
    text: `${stats.blocked_attempts} attacks were blocked and none succeeded.`,
  };
}

function EventRow({ event }) {
  const [open, setOpen] = useState(false);
  const bodyId = useId();

  const state = stateFor({
    outcome: event.outcome,
    severity: event.severity,
    jailbreakSuccess: event.jailbreak_success,
  });

  return (
    <li className={`event event-${state}`}>
      <h3>
        <button
          type="button"
          className="event-head"
          aria-expanded={open}
          aria-controls={bodyId}
          onClick={() => setOpen(!open)}
        >
          <ChevronRight size={20} className="chev" aria-hidden="true" />

          <span className="event-main">
            <span className="event-summary">{event.summary}</span>
            <span className="event-sub">
              {prettyCategory(event.category)} ·{" "}
              {event.source === "red_team" ? "Red Team" : "Chat"}
            </span>
          </span>

          <StatusBadge state={state} />
          <SeverityBadge level={event.severity} />
          <span className="num event-risk" aria-label={`Risk ${event.risk_score}`}>
            {event.risk_score}
          </span>
          <time className="num event-time" dateTime={event.timestamp}>
            {formatTime(event.timestamp)}
          </time>
        </button>
      </h3>

      {open && (
        <div id={bodyId} className="event-body">
          <dl className="kv">
            <dt>Source</dt>
            <dd>
              {event.source === "red_team"
                ? `Red Team (assessment ${event.assessment_id})`
                : `Chat (session ${String(event.session_id).slice(0, 8)})`}
            </dd>

            <dt>Confidence</dt>
            <dd className="num">{Math.round(event.confidence * 100)}%</dd>

            <dt>Model resisted</dt>
            <dd>
              {event.model_resisted === null ? "Unknown" : event.model_resisted ? "Yes" : "No"}
            </dd>

            {event.details?.contained && (
              <>
                <dt>Honeypot</dt>
                <dd>Attacker was served decoy data and was not told.</dd>
              </>
            )}

            <dt>Host alert</dt>
            <dd>{event.alert_triggered ? "Sent" : "Not triggered"}</dd>

            {event.details?.reason && (
              <>
                <dt>Reason</dt>
                <dd>{event.details.reason}</dd>
              </>
            )}

            {event.details?.prompt_excerpt && (
              <>
                <dt>Prompt (redacted)</dt>
                <dd className="quote">{event.details.prompt_excerpt}</dd>
              </>
            )}

            {event.details?.response_excerpt && (
              <>
                <dt>Response (redacted)</dt>
                <dd className="quote">{event.details.response_excerpt}</dd>
              </>
            )}

            <dt>Event ID</dt>
            <dd className="mono">{event.event_id}</dd>
          </dl>
        </div>
      )}
    </li>
  );
}

const FILTERS = [
  { id: "ALL", label: "All" },
  { id: "MEDIUM", label: "Medium and up" },
  { id: "HIGH", label: "High and up" },
  { id: "CRITICAL", label: "Critical" },
  { id: "HONEYPOT", label: "Honeypot" },
];

function SecurityPage({ refreshKey }) {
  const [stats, setStats] = useState(null);
  const [events, setEvents] = useState([]);
  const [filter, setFilter] = useState("ALL");
  const [error, setError] = useState("");
  const [testing, setTesting] = useState(false);
  const [testSent, setTestSent] = useState(false);

  const load = useCallback(async () => {
    try {
      const query =
        filter === "ALL" || filter === "HONEYPOT"
          ? ""
          : `&min_severity=${filter.toLowerCase()}`;

      const [statsData, eventsData] = await Promise.all([
        getJSON("/security/stats"),
        getJSON(`/security/events?limit=100${query}`),
      ]);

      setStats(statsData);
      setEvents(
        filter === "HONEYPOT"
          ? eventsData.events.filter((e) => e.details?.contained)
          : eventsData.events
      );
      setError("");
    } catch {
      setError("Connection failed. Check that the backend is running, then refresh.");
    }
  }, [filter]);

  useEffect(() => {
    const first = setTimeout(load, 0);
    const timer = setInterval(load, 5000);

    return () => {
      clearTimeout(first);
      clearInterval(timer);
    };
  }, [load, refreshKey]);

  const sendTest = async () => {
    setTesting(true);
    setTestSent(false);

    try {
      await postJSON("/security/alerts/test");
      setTestSent(true);
    } catch {
      setError("The test alert could not be sent. Check the backend log.");
    } finally {
      setTesting(false);
    }
  };

  if (!stats) {
    return (
      <div className="page">
        <div className="page-inner">
          {error ? (
            <div className="form-error" role="alert">
              <CircleAlert size={20} aria-hidden="true" />
              {error}
            </div>
          ) : (
            <div className="empty" role="status">
              <Spinner label="Loading security monitor" />
              <p>Loading security monitor…</p>
            </div>
          )}
        </div>
      </div>
    );
  }

  const avg = stats.average_risk_score;
  const level = levelFor(avg);
  const attacked = stats.system_status !== "PROTECTED";
  const verdict = verdictFor(stats);

  return (
    <div className="page">
      <div className="page-inner">

        <header className="mon-head">
          <div>
            <h1>Security Monitor</h1>
            <p>Detection, risk scoring and Red Team results for the model.</p>
          </div>

          <div className="mon-actions">
            <Button variant="secondary" icon={BellRing} onClick={sendTest} disabled={testing}>
              Send test alert
            </Button>

            <Button variant="ghost" icon={RefreshCw} onClick={load}>
              Refresh
            </Button>

            <span className="sr-only" role="status">
              {testSent ? "Test alert sent" : ""}
            </span>
          </div>
        </header>

        {error && (
          <div className="form-error" role="alert">
            <CircleAlert size={20} aria-hidden="true" />
            {error}
          </div>
        )}

        {/* ---------- the one big surface: verdict + key numbers ---------- */}

        <section className="mon-hero" aria-labelledby="verdict-title">
          <RiskMeter value={avg} level={level} />

          <div className="mon-verdict">
            <h2 id="verdict-title">{verdict.title}</h2>
            <p>{verdict.text}</p>

            <div className="verdict-badges">
              {attacked ? (
                <StatusBadge state="critical" label="Under attack" />
              ) : (
                <StatusBadge state="safe" label="Protected" />
              )}

              <span>
                Threat level, last 15 min <SeverityBadge level={stats.current_threat_level} />
              </span>
            </div>
          </div>

          <div className="mon-key">
            <MetricCard icon={Target} label="Attack attempts" value={stats.total_attempts} />
            <MetricCard
              icon={ShieldCheck}
              label="Blocked"
              value={stats.blocked_attempts}
              tone="ok"
            />
            <MetricCard
              icon={ShieldX}
              label="Successful jailbreaks"
              value={stats.successful_jailbreaks}
              tone={stats.successful_jailbreaks ? "crit" : ""}
            />
          </div>
        </section>

        <section className="mon-sub" aria-label="More measurements">
          <MetricCard icon={Ghost} label="Honeypot interactions" value={stats.honeypot_interactions} />
          <MetricCard label="Contained sessions" value={stats.honeypot_sessions} />
          <MetricCard label="High-risk events" value={stats.high_risk_events} />
          <MetricCard
            label="Critical events"
            value={stats.critical_events}
            tone={stats.critical_events ? "crit" : ""}
          />
          <MetricCard
            label="Jailbreak success rate"
            value={stats.jailbreak_success_rate}
            suffix="%"
          />
        </section>

        {/* ---------- categories ---------- */}

        <section className="mon-section" aria-labelledby="cat-title">
          <h2 id="cat-title">Attack categories</h2>

          {Object.keys(stats.by_category).length === 0 ? (
            <p className="muted">No attacks recorded yet.</p>
          ) : (
            <ul className="cat-bars">
              {Object.entries(stats.by_category)
                .sort((a, b) => b[1] - a[1])
                .map(([category, count]) => (
                  <li key={category}>
                    <span>{prettyCategory(category)}</span>

                    <div className="cat-track" aria-hidden="true">
                      <div
                        className="cat-fill"
                        style={{ transform: `scaleX(${count / stats.total_attempts})` }}
                      />
                    </div>

                    <b className="num">{count}</b>
                  </li>
                ))}
            </ul>
          )}
        </section>

        {/* ---------- events ---------- */}

        <section className="mon-section" aria-labelledby="events-title">
          <div className="mon-section-head">
            <h2 id="events-title">Recent security events</h2>

            <div className="filters" role="group" aria-label="Filter events">
              {FILTERS.map(({ id, label }) => (
                <button
                  key={id}
                  type="button"
                  className={filter === id ? "chip active" : "chip"}
                  aria-pressed={filter === id}
                  onClick={() => setFilter(id)}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          {events.length === 0 ? (
            <EmptyState icon={ShieldCheck} title="No events match this filter">
              Send a jailbreak attempt in the chat or run a Red Team assessment and events
              will appear here.
            </EmptyState>
          ) : (
            <ul className="events">
              {events.map((event) => (
                <EventRow key={event.event_id} event={event} />
              ))}
            </ul>
          )}
        </section>

        <p className="foot-badge">
          <Badge tone="accent">Live</Badge> Refreshes every 5 seconds.
        </p>

      </div>
    </div>
  );
}

export default SecurityPage;
