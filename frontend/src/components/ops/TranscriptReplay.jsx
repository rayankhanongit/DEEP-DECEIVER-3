import { useEffect, useRef } from "react";

import { Badge, SeverityBadge } from "../ui/Badge";

const pretty = (s) => (s || "").replaceAll("_", " ");
const time = (iso) => (iso ? new Date(iso).toLocaleTimeString() : "Unavailable");

function TranscriptReplay({ session, turns, selected, onSelect }) {
  const demo = session.origin === "demo";
  const rowRef = useRef(null);
  const boxRef = useRef(null);

  // keep the selected exchange in view inside the transcript box only (the page never jumps)
  useEffect(() => {
    const box = boxRef.current;
    const row = rowRef.current;

    if (box && row) box.scrollTop = row.offsetTop - (box.clientHeight - row.clientHeight) / 2;
  }, [selected]);

  return (
    <section className="ops-card" aria-labelledby="tr-title">
      <header className="ops-card-head">
        <h2 id="tr-title">Honeypot transcript replay</h2>
        <Badge tone={demo ? "warn" : "info"}>
          {demo ? "DEMO: scripted replies, not model output" : "LIVE: stored conversation"}
        </Badge>
      </header>

      <div className="tr-scroll" ref={boxRef} role="group" aria-label="Transcript, attacker view beside operator view">
        <div className="tr-head">
          <div>Simulated attacker view <small>what the sender saw</small></div>
          <div>Operator security view <small>what the system recorded</small></div>
        </div>

        {turns.map((t) => {
          const on = selected === t.index;

          return (
            <div key={t.index} ref={on ? rowRef : null}
              className={`tr-row${on ? " tr-on" : ""}${t.route === "shadow" ? " tr-hot" : ""}`}>
              <button type="button" className="tr-cell tr-attacker" aria-pressed={on} onClick={() => onSelect(t.index)}>
                <span className="tr-turn">#{t.index} <time>{time(t.ts)}</time></span>
                <span className="tr-bubble tr-user"><b>User</b>{t.user}</span>
                <span className="tr-bubble tr-bot"><b>Assistant</b>{t.reply}</span>
              </button>

              <button type="button" className="tr-cell tr-operator" aria-pressed={on} onClick={() => onSelect(t.index)}>
                <span className="tr-chips">
                  <SeverityBadge level={t.severity} />
                  <Badge tone={t.route === "shadow" ? "crit" : t.route === "hold" ? "warn" : "ok"}>
                    {t.route === "shadow" ? "Honeypot" : t.route === "hold" ? "Held" : "Production"}
                  </Badge>
                  {t.stage && <Badge tone="info">{pretty(t.stage)}</Badge>}
                </span>
                <span className="tr-facts">
                  <span>Category: {pretty(t.attack_category)}</span>
                  <span>Decision: {t.action} ({pretty(t.decision_reason)})</span>
                  <span>Risk score: {t.risk.toFixed(2)}</span>
                  <span>Sensors: {t.filter_flagged ? `fast filter flagged${t.filter_patterns.length ? ` (${t.filter_patterns.length} pattern${t.filter_patterns.length > 1 ? "s" : ""})` : ""}` : "fast filter clear"}</span>
                  <span>Source: {demo ? "offline demo detector" : t.model || "unavailable"}</span>
                  {t.event_id && <span>Event: <code>{t.event_id.slice(0, 10)}</code></span>}
                </span>
              </button>
            </div>
          );
        })}
      </div>
    </section>
  );
}

export default TranscriptReplay;
