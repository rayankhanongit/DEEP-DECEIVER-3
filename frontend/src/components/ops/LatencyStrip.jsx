import { Badge } from "../ui/Badge";

const TARGET_MS = 100;

const isNum = (v) => typeof v === "number";
const ms = (v) => (isNum(v) ? `${Math.round(v)} ms` : "Unavailable");

/** What actually handled a request, from what the pipeline recorded. */
function pathLabel(origin, engine) {
  if (origin === "demo") return "Sensors + offline demo detector";
  if (engine === "sensor-fallback") return "Sensors only (agents rate-limited, sensor fallback)";
  if (engine === "unavailable") return "Sensors only (agents unavailable, message held)";

  return "Sensors + LLM agents";
}

function Meter({ timings, origin }) {
  const sensors = timings?.sensors;
  const agents = timings?.agents;

  if (!isNum(sensors) || !isNum(agents)) return <p className="ops-muted">No timing recorded for this request.</p>;

  const scale = Math.max(TARGET_MS * 2, (sensors + agents) * 1.1);
  const pct = (v) => `${(v / scale) * 100}%`;

  return (
    <div className="lat-meter" role="img"
      aria-label={`Fast path ${sensors} ms, agent path ${agents} ms, target ${TARGET_MS} ms`}>
      <div className="lat-bar">
        <span className="lat-seg lat-fast" style={{ width: pct(sensors) }} />
        <span className={origin === "demo" ? "lat-seg lat-agent lat-sim" : "lat-seg lat-agent"}
          style={{ width: pct(agents) }} />
        <span className="lat-target" style={{ left: pct(TARGET_MS) }}><i>{TARGET_MS} ms target</i></span>
      </div>
      <div className="lat-legend">
        <span><b className="lat-key lat-fast" /> Fast path</span>
        <span><b className="lat-key lat-agent" /> Agent path</span>
      </div>
    </div>
  );
}

function History({ samples }) {
  if (samples.length < 2) return <p className="ops-muted">History appears after at least two recorded requests.</p>;

  const rows = samples.slice(-30);
  const top = Math.max(TARGET_MS * 1.5, ...rows.map((r) => r.timings_ms.total || 0));

  return (
    <div className="lat-history" role="img" aria-label={`Total latency of the last ${rows.length} requests`}>
      {rows.map((r, i) => {
        const total = r.timings_ms.total;
        const ok = isNum(total) && total <= TARGET_MS;

        return (
          <span key={`${r.session_id}-${r.turn}-${i}`} className={ok ? "lat-col ok" : "lat-col over"}
            style={{ height: `${Math.max(4, ((total || 0) / top) * 100)}%` }}
            title={`${r.origin} #${r.turn}: ${total} ms total`} />
        );
      })}
      <span className="lat-hline" style={{ bottom: `${(TARGET_MS / top) * 100}%` }} />
    </div>
  );
}

function Row({ label, s, note }) {
  const cell = (v) => (isNum(v) ? `${Math.round(v)} ms` : "n/a");

  return (
    <tr>
      <th scope="row">{label}{note && <small> {note}</small>}</th>
      <td>{s?.n ?? 0}</td>
      <td>{cell(s?.avg)}</td>
      <td>{cell(s?.median)}</td>
      <td>{s?.p95 == null ? "needs 20+" : cell(s.p95)}</td>
    </tr>
  );
}

function LatencyStrip({ turn, origin, data }) {
  const timings = turn?.timings_ms;
  const stats = data?.stats?.[origin] || {};
  const samples = (data?.samples || []).filter((s) => s.origin === origin);

  const fast = timings?.sensors;
  const agent = timings?.agents;
  const total = timings?.total;

  const demo = origin === "demo";
  const meets = (v) => (isNum(v) ? (v <= TARGET_MS ? "within" : "over") : null);

  return (
    <section className="ops-card" aria-labelledby="lat-title">
      <header className="ops-card-head">
        <h2 id="lat-title">Latency: fast path vs agent path</h2>
        <Badge tone={demo ? "warn" : "info"}>{demo ? "DEMO observations" : "LIVE observations"}</Badge>
      </header>

      <div className="lat-grid">
        <div className="lat-stat">
          <span className="lat-label">Fast path (sensors)</span>
          <strong>{ms(fast)}</strong>
          {meets(fast) && <Badge tone={meets(fast) === "within" ? "ok" : "warn"}>
            {meets(fast) === "within" ? `Within ${TARGET_MS} ms target` : `Over ${TARGET_MS} ms target`}</Badge>}
        </div>

        <div className="lat-stat">
          <span className="lat-label">Agent path</span>
          <strong>{ms(agent)}</strong>
          {demo ? <Badge tone="warn">Simulated: no model call</Badge>
            : turn?.engine === "unavailable" ? <Badge tone="warn">Agents unavailable</Badge>
            : meets(agent) && <Badge tone={meets(agent) === "within" ? "ok" : "warn"}>
              {meets(agent) === "within" ? "Within target" : `Over ${TARGET_MS} ms target`}</Badge>}
        </div>

        <div className="lat-stat">
          <span className="lat-label">Total processing</span>
          <strong>{ms(total)}</strong>
          {meets(total) && <Badge tone={meets(total) === "within" ? "ok" : "warn"}>
            {meets(total) === "within" ? "Within target" : "Over target"}</Badge>}
        </div>
      </div>

      {turn ? (
        <p className="ops-muted">
          Request #{turn.index} handled by: <b>{pathLabel(origin, turn.engine)}</b>.
          {" "}Includes the time to produce the reply ({ms(timings?.reply)}).
        </p>
      ) : <p className="ops-muted">No request selected.</p>}

      <Meter timings={timings} origin={origin} />

      <div className="lat-lower">
        <div>
          <h3>Recorded statistics ({origin})</h3>
          <table className="lat-table">
            <thead><tr><th>Stage</th><th>Requests</th><th>Average</th><th>Median</th><th>p95</th></tr></thead>
            <tbody>
              <Row label="Fast path" s={stats.sensors} />
              <Row label="Agent path" s={stats.agents} note={demo ? "(no model)" : ""} />
              <Row label="Total" s={stats.total} />
            </tbody>
          </table>
        </div>

        <div>
          <h3>Total latency, recent requests</h3>
          <History samples={samples} />
        </div>
      </div>
    </section>
  );
}

export default LatencyStrip;
