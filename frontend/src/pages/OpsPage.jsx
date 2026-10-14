import { useCallback, useEffect, useRef, useState } from "react";
import { FileDown, FileJson, Play, RotateCcw, Trash2 } from "lucide-react";

import "../styles/ops.css";
import { API, authHeaders, getJSON, postJSON } from "../api";
import { downloadText, toJson } from "../utils/download";
import { Badge } from "../components/ui/Badge";
import Button from "../components/ui/Button";
import LatencyStrip from "../components/ops/LatencyStrip";
import KillChainTimeline from "../components/ops/KillChainTimeline";
import TranscriptReplay from "../components/ops/TranscriptReplay";

const STEP_MS = 650;                                   // short, presentation-friendly pacing
const REFRESH_MS = 15000;

const reducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function OpsPage() {
  const [sessions, setSessions] = useState([]);
  const [latency, setLatency] = useState(null);
  const [sessionId, setSessionId] = useState("");
  const [session, setSession] = useState(null);
  const [selected, setSelected] = useState(null);
  const [reveal, setReveal] = useState(null);          // null = show everything
  const [demo, setDemo] = useState({ state: "idle" });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const timer = useRef(null);

  const loadSession = useCallback(async (id) => {
    setSession(await getJSON(`/ops/sessions/${encodeURIComponent(id)}`));
  }, []);

  const refresh = useCallback(async (pick) => {
    try {
      const [list, lat] = await Promise.all([getJSON("/ops/sessions"), getJSON("/ops/latency?limit=200")]);

      setSessions(list.sessions);
      setLatency(lat);
      setError("");

      const id = pick ?? sessionId ?? "";
      const target = list.sessions.some((s) => s.session_id === id) ? id : list.sessions[0]?.session_id || "";

      setSessionId(target);

      if (target) await loadSession(target);
      else setSession(null);
    } catch (e) {
      setError(e.message.includes("401") || e.message.includes("403")
        ? "Operator access is required."
        : "Unable to load operations data. Is the backend running?");
    } finally {
      setLoading(false);
    }
  }, [sessionId, loadSession]);

  useEffect(() => {
    const first = setTimeout(() => refresh(), 0);

    return () => clearTimeout(first);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    // modest polling for live traffic; paused while the tab is hidden or the walkthrough runs
    const id = setInterval(() => {
      if (document.visibilityState === "visible" && demo.state !== "running") refresh();
    }, REFRESH_MS);

    return () => clearInterval(id);
  }, [refresh, demo.state]);

  useEffect(() => () => clearInterval(timer.current), []);

  const runDemo = async () => {
    clearInterval(timer.current);
    setNote("");
    setDemo({ state: "running" });

    try {
      const trace = await postJSON("/ops/demo/run");

      setSession(trace);
      setSessionId(trace.session_id);
      setSelected(null);

      const total = trace.turns.length;

      const finish = async () => {
        clearInterval(timer.current);
        setReveal(null);
        setDemo({ state: "done", steps: total });
        await refresh(trace.session_id);
      };

      if (reducedMotion()) {
        await finish();
        return;
      }

      let shown = 0;

      setReveal(0);

      timer.current = setInterval(() => {
        shown += 1;
        setReveal(shown);

        if (shown >= total) finish();
      }, STEP_MS);
    } catch {
      setDemo({ state: "error" });
      setNote("The walkthrough could not start. Is the backend running with OPERATOR_TOKEN set?");
    }
  };

  const resetDemo = async () => {
    clearInterval(timer.current);

    try {
      const response = await fetch(`${API}/ops/demo`, { method: "DELETE", headers: authHeaders() });

      if (!response.ok) throw new Error("reset failed");

      setReveal(null);
      setDemo({ state: "idle" });
      setSession(null);
      setSessionId("");
      setNote("Demo sessions cleared. Live sessions were not touched.");
      await refresh("");
    } catch {
      setNote("Could not clear the demo sessions.");
    }
  };

  const exportPdf = async () => {
    try {
      const response = await fetch(`${API}/ops/sessions/${encodeURIComponent(sessionId)}/report.pdf`, { headers: authHeaders() });

      if (!response.ok) throw new Error("report failed");

      const name = /filename="([^"]+)"/.exec(response.headers.get("Content-Disposition") || "")?.[1] || "incident-report.pdf";
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");

      link.href = url;
      link.download = name;
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setNote(`Report downloaded: ${name}`);
    } catch {
      setNote("The incident report could not be generated.");
    }
  };

  const exportJson = () => {
    downloadText(`session-${session.session_id}.json`, toJson(session), "application/json");
    setNote("Session JSON downloaded.");
  };

  const turns = session ? session.turns.slice(0, reveal ?? session.turns.length) : [];
  const current = turns.find((t) => t.index === selected) || turns[turns.length - 1] || null;
  const isDemo = session?.origin === "demo";
  const running = demo.state === "running";

  if (loading) return <div className="ops-wrap"><p className="ops-muted" role="status">Loading operations data…</p></div>;

  return (
    <div className="ops-wrap">
      <header className="ops-top">
        <div>
          <h1>Command center</h1>
          <p className="ops-muted">Latency, attack walkthrough, kill chain and honeypot replay for one session.</p>
        </div>

        <div className="ops-actions">
          <Button variant="primary" icon={demo.state === "done" ? RotateCcw : Play} onClick={runDemo} disabled={running}>
            {running ? "Running…" : demo.state === "done" ? "Replay demo attack" : "Run demo attack"}
          </Button>
          <Button variant="ghost" icon={Trash2} onClick={resetDemo} disabled={running}>Clear demo</Button>
        </div>
      </header>

      {error && <div className="ops-alert" role="alert">{error}</div>}
      {note && <div className="ops-note" role="status">{note}</div>}

      {isDemo && (
        <div className="ops-demo" role="status">
          <Badge tone="warn">DEMO MODE</Badge>
          <span>
            Scripted, harmless attack in an isolated session. Detection uses the offline demo detector, not the LLM
            agents, and nothing is written to the event store.
            {running && ` Step ${Math.min(reveal ?? 0, session.turns.length)} of ${session.turns.length}…`}
          </span>
        </div>
      )}

      {demo.state === "done" && session && (
        <p className="ops-summary" role="status">
          Walkthrough complete: {demo.steps} simulated steps,{" "}
          {session.turns.filter((t) => t.sentry_flagged).length} detections,{" "}
          {session.turns[session.turns.length - 1].completed_stages.length} kill-chain stages reached, 0 stored incident events (demo).
        </p>
      )}

      {sessions.length === 0 ? (
        <div className="ops-empty">
          <h2>No sessions recorded yet</h2>
          <p className="ops-muted">Send a message in the assistant, or run the demo attack to see the full workflow.</p>
        </div>
      ) : (
        <>
          <div className="ops-bar">
            <label>
              <span>Session</span>
              <select value={sessionId} disabled={running}
                onChange={(e) => { setSessionId(e.target.value); setSelected(null); loadSession(e.target.value); }}>
                {sessions.map((s) => (
                  <option key={s.session_id} value={s.session_id}>
                    {s.origin === "demo" ? "DEMO" : "LIVE"} · {s.session_id.slice(0, 14)} · {s.turns} msg · {s.severity}
                  </option>
                ))}
              </select>
            </label>

            <div className="ops-actions">
              <Button icon={FileDown} onClick={exportPdf} disabled={!session || running}>Export incident report (PDF)</Button>
              <Button variant="ghost" icon={FileJson} onClick={exportJson} disabled={!session || running}>Session JSON</Button>
            </div>
          </div>

          {session && turns.length > 0 && (
            <>
              <LatencyStrip turn={current} origin={session.origin} data={latency} />

              <KillChainTimeline stages={session.kill_chain_stages} turns={turns} selected={current.index}
                onSelect={setSelected} origin={session.origin} sessionId={session.session_id} />

              <TranscriptReplay session={session} turns={turns} selected={current.index} onSelect={setSelected} />
            </>
          )}
        </>
      )}
    </div>
  );
}

export default OpsPage;
