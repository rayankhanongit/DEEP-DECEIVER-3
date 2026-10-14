import { useEffect, useState } from "react";

import { authHeaders } from "../api";

const pct = (v) => (v == null ? "n/a" : `${(v * 100).toFixed(1)}%`);
const ci = (c) => (c ? `${pct(c[0])} – ${pct(c[1])}` : "n/a");

function Bar({ value, tone }) {
  return (
    <div className="bench-track" role="img" aria-label={pct(value)}>
      <div className={`bench-fill ${tone}`} style={{ width: `${Math.round((value || 0) * 100)}%` }} />
    </div>
  );
}

function BenchmarkPage() {
  const [rows, setRows] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch("http://127.0.0.1:8000/soc/benchmark", { headers: authHeaders() })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error("bad status"))))
      .then((d) => setRows(d.rows))
      .catch(() => setError("Unable to load benchmark results. Is the backend running?"));
  }, []);

  if (error) return <main className="soc-container"><div className="soc-error"><p>{error}</p></div></main>;
  if (!rows) return <main className="soc-container"><div className="soc-loading">Loading benchmark…</div></main>;

  return (
    <main className="soc-container">
      <div className="soc-header">
        <div>
          <h2>Detection benchmark</h2>
          <p>Held-out set, recall = attacks caught, 95% Wilson interval</p>
        </div>
      </div>

      {rows.map((r) => (
        <section key={r.mode} className="bench-row">
          <h3>{r.label}</h3>
          <p>Recall {pct(r.recall)} <span className="bench-ci">({ci(r.recall_ci)}, n={r.attacks})</span></p>
          <Bar value={r.recall} tone="good" />
          <p>False positives {pct(r.false_positive_rate)} <span className="bench-ci">({ci(r.fpr_ci)}, n={r.benign})</span></p>
          <Bar value={r.false_positive_rate} tone="bad" />
          {r.errors > 0 && (
            <p className="bench-warn">
              Incomplete: {r.errors} cases never got an answer (rate limit), so these rates cover only the answered cases.
            </p>
          )}
          {r.latency_ms && <p className="bench-ci">Latency p50 {r.latency_ms.p50} ms, p95 {r.latency_ms.p95} ms</p>}
        </section>
      ))}
    </main>
  );
}

export default BenchmarkPage;
