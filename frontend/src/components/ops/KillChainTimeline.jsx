import { useState } from "react";

import { Badge, SeverityBadge } from "../ui/Badge";

const pretty = (s) => (s || "").replaceAll("_", " ");
const time = (iso) => (iso ? new Date(iso).toLocaleTimeString() : "Unavailable");

/** One event per kill-chain stage: the first message the pipeline assigned to it. */
function buildEvents(stages, turns) {
  const firstShadow = turns.find((t) => t.route === "shadow")?.index;

  return stages.map((stage) => {
    const turn = turns.find((t) => t.stage === stage);

    if (!turn) return { stage, turn: null, status: "Not observed", tone: "neutral" };

    if (turn.route === "shadow") {
      return turn.index === firstShadow
        ? { stage, turn, status: "Escalated: honeypot", tone: "crit" }
        : { stage, turn, status: "Contained", tone: "warn" };
    }

    return turn.sentry_flagged || turn.filter_flagged
      ? { stage, turn, status: "Detection confirmed", tone: "warn" }
      : { stage, turn, status: "Observed", tone: "info" };
  });
}

function KillChainTimeline({ stages, turns, selected, onSelect, origin, sessionId }) {
  const [open, setOpen] = useState(null);

  const events = buildEvents(stages, turns);
  const reached = events.filter((e) => e.turn).length;
  const detail = events.find((e) => e.stage === open && e.turn);

  return (
    <section className="ops-card" aria-labelledby="kc-title">
      <header className="ops-card-head">
        <h2 id="kc-title">Kill-chain timeline</h2>
        <Badge tone={origin === "demo" ? "warn" : "info"}>{origin === "demo" ? "DEMO session" : "LIVE session"}</Badge>
      </header>

      <p className="ops-muted">
        Stages come from the kill-chain tracker; a stage is shown as reached only when a message was assigned to it.
        {" "}{reached} of {stages.length} reached. Session <code>{sessionId}</code>.
      </p>

      <ol className="kc-line">
        {events.map(({ stage, turn, status, tone }) => {
          const active = turn && selected === turn.index;

          return (
            <li key={stage} className={`kc-step kc-${turn ? tone : "none"}${active ? " kc-active" : ""}`}>
              <button type="button" disabled={!turn} aria-expanded={open === stage}
                onClick={() => { setOpen(open === stage ? null : stage); if (turn) onSelect(turn.index); }}>
                <span className="kc-dot" aria-hidden="true" />
                <span className="kc-name">{pretty(stage)}</span>
                <Badge tone={tone}>{status}</Badge>
                <span className="kc-meta">{turn ? `#${turn.index} · ${time(turn.ts)}` : "No event"}</span>
              </button>
            </li>
          );
        })}
      </ol>

      {detail && (
        <dl className="kc-detail">
          <div><dt>Stage</dt><dd>{pretty(detail.stage)}</dd></div>
          <div><dt>Message</dt><dd>#{detail.turn.index} at {time(detail.turn.ts)}</dd></div>
          <div><dt>Severity</dt><dd><SeverityBadge level={detail.turn.severity} /></dd></div>
          <div><dt>Category</dt><dd>{pretty(detail.turn.attack_category)}</dd></div>
          <div><dt>Decision</dt><dd>{detail.turn.action} ({pretty(detail.turn.decision_reason)})</dd></div>
          <div><dt>Risk score</dt><dd>{detail.turn.risk.toFixed(2)}</dd></div>
          <div className="kc-wide"><dt>Excerpt</dt><dd>{detail.turn.user}</dd></div>
        </dl>
      )}
    </section>
  );
}

export default KillChainTimeline;
