import { StrictMode, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

type Event = {
  eventId: string;
  timestamp: string;
  eventType: string;
  riskLevel: string;
  toolName?: string;
  decision?: string;
  summary: string;
  latencyMs: number;
  judgeTokens: number;
};

type Session = {
  sessionId: string;
  label: string;
  targetName: string;
  startedAt: string;
  mode: string;
  events: Event[];
  metrics: { totalToolCalls: number; allows: number; blocks: number; askUser: number; quarantines: number; deterministicResolutionRate: number; judgeEscalationRate: number; judgeTokens: number; cacheHitRate: number };
};

function Metric({ label, value, note }: { label: string; value: string | number; note: string }) {
  return <article className="metric"><span>{label}</span><strong>{value}</strong><small>{note}</small></article>;
}

function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [selected, setSelected] = useState<Event | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    fetch("/api/sessions/offline-day3-demo")
      .then(async (response) => { if (!response.ok) throw new Error("Dashboard API unavailable"); return response.json() as Promise<Session>; })
      .then((value) => { setSession(value); setSelected(value.events.at(-1) ?? null); })
      .catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Unable to load session"));
  }, []);
  const latestCritical = useMemo<Event | undefined>(() => session?.events.filter((event) => event.riskLevel === "critical").at(-1), [session]);

  if (error) return <main className="center"><section className="empty"><p className="eyebrow">CONNECTION ERROR</p><h1>Security data is unavailable</h1><p>{error}. Start the localhost API and refresh.</p></section></main>;
  if (!session) return <main className="center"><p className="loading">Loading verified session…</p></main>;

  return <div className="shell">
    <aside>
      <div className="brand"><div className="mark">W</div><div><strong>MCP Warden</strong><span>Security console</span></div></div>
      <nav aria-label="Primary"><a className="active" href="#overview">Overview</a><a href="#timeline">Session timeline</a><a href="#policy">Policy</a><a href="#trust">Trust baseline</a></nav>
      <div className="connection"><i></i><span>Local enforcement online</span><small>127.0.0.1 only</small></div>
    </aside>
    <main>
      <header><div><p className="eyebrow">PROTECTED SESSION</p><h1>Runtime overview</h1><p className="subtitle">One target. Every call inspected before execution.</p></div><div className="header-actions"><span className="badge">{session.label}</span><span className="mode">{session.mode}</span></div></header>
      <section className="metrics" id="overview">
        <Metric label="Tool calls" value={session.metrics.totalToolCalls} note={`${session.targetName} target`} />
        <Metric label="Deterministic" value={`${Math.round(session.metrics.deterministicResolutionRate * 100)}%`} note="Resolved without GPT" />
        <Metric label="Blocked" value={session.metrics.blocks} note="Stopped pre-execution" />
        <Metric label="Judge tokens" value={session.metrics.judgeTokens} note="Recorded replay uses zero" />
      </section>
      {latestCritical && <section className="alert"><span className="risk-dot critical"></span><div><p className="eyebrow">LATEST CRITICAL EVENT</p><strong>{latestCritical.summary}</strong></div><button onClick={() => setSelected(latestCritical)}>Inspect event</button></section>}
      <section className="workspace" id="timeline">
        <div className="panel timeline"><div className="panel-head"><div><p className="eyebrow">SESSION TIMELINE</p><h2>Enforcement activity</h2></div><code>{session.sessionId}</code></div>
          <div className="events">{session.events.map((event) => <button key={event.eventId} className={`event ${selected?.eventId === event.eventId ? "selected" : ""}`} onClick={() => setSelected(event)}>
            <span className={`risk-dot ${event.riskLevel}`}></span><span className="event-time">{new Date(event.timestamp).toLocaleTimeString([], { hour12: false })}</span><span className="event-copy"><strong>{event.toolName ?? event.eventType}</strong><small>{event.summary}</small></span>{event.decision && <span className={`decision ${event.decision.toLowerCase()}`}>{event.decision}</span>}<span className="latency">{event.latencyMs} ms</span>
          </button>)}</div>
        </div>
        <div className="panel detail"><div className="panel-head"><div><p className="eyebrow">EVENT INSPECTOR</p><h2>{selected?.eventType ?? "Select an event"}</h2></div></div>
          {selected && <div className="detail-body"><div className="detail-grid"><label>Risk<strong className={selected.riskLevel}>{selected.riskLevel}</strong></label><label>Decision<strong>{selected.decision ?? "—"}</strong></label><label>Latency<strong>{selected.latencyMs} ms</strong></label><label>Judge tokens<strong>{selected.judgeTokens}</strong></label></div><h3>Evidence summary</h3><p>{selected.summary}</p><h3>Audit identity</h3><code>{selected.eventId}</code><div className="chain"><i></i> Recorded fixture event • raw secrets unavailable</div></div>}
        </div>
      </section>
      <footer><span>MCP Warden v0.1.0</span><span>Dashboard is outside the enforcement path</span></footer>
    </main>
  </div>;
}

const rootElement = document.getElementById("root");
if (!rootElement) throw new Error("Dashboard root element is missing");
createRoot(rootElement).render(<StrictMode><App /></StrictMode>);
