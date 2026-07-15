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
  staticLabel?: string;
};
type PolicyDetail = { yaml: string; valid: boolean; mode: string };
type Scenario = { id: string; title: string; category: string; expected: string; actual?: string; summary: string };
type ScenarioResult = { scenarioId: string; expected: string; actual: string; matched: boolean; summary: string };

function snapshotUrl(file: string): string {
  return new URL(`snapshot/${file}`, document.baseURI).toString();
}

function Metric({ label, value, note }: { label: string; value: string | number; note: string }) {
  return <article className="metric"><span>{label}</span><strong>{value}</strong><small>{note}</small></article>;
}

function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [selected, setSelected] = useState<Event | null>(null);
  const [error, setError] = useState("");
  const [policy, setPolicy] = useState<PolicyDetail | null>(null);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [labResult, setLabResult] = useState<ScenarioResult | null>(null);
  const [labBusy, setLabBusy] = useState("");
  const [readOnly, setReadOnly] = useState(false);
  useEffect(() => {
    const load = async () => {
      try {
        const response = await fetch("/api/sessions/offline-day3-demo");
        if (!response.ok) throw new Error("Dashboard API unavailable");
        const value = await response.json() as Session;
        setSession(value); setSelected(value.events.at(-1) ?? null);
      } catch {
        try {
          const response = await fetch(snapshotUrl("session.json"));
          if (!response.ok) throw new Error("Recorded snapshot unavailable");
          const value = await response.json() as Session;
          const decisions = value.events.filter((event) => event.decision);
          value.metrics = { totalToolCalls: decisions.length, allows: decisions.filter((event) => event.decision === "ALLOW").length, blocks: decisions.filter((event) => event.decision === "BLOCK").length, askUser: decisions.filter((event) => event.decision === "ASK_USER").length, quarantines: decisions.filter((event) => event.decision === "QUARANTINE").length, deterministicResolutionRate: 1, judgeEscalationRate: 0, judgeTokens: 0, cacheHitRate: 0 };
          setReadOnly(true); setSession(value); setSelected(value.events.at(-1) ?? null);
        } catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to load session"); }
      }
    };
    void load();
  }, []);
  useEffect(() => { fetch("/api/policy").then((response) => response.ok ? response.json() as Promise<PolicyDetail> : null).then(setPolicy).catch(() => setPolicy(null)); }, []);
  useEffect(() => {
    fetch("/api/demo/scenarios").then(async (response) => { if (!response.ok) throw new Error(); return response.json() as Promise<Scenario[]>; }).then(setScenarios)
      .catch(() => { fetch(snapshotUrl("scenarios.json")).then((response) => response.json() as Promise<Scenario[]>).then(setScenarios).catch(() => setScenarios([])); });
  }, []);
  const latestCritical = useMemo<Event | undefined>(() => session?.events.filter((event) => event.riskLevel === "critical").at(-1), [session]);

  async function runScenario(scenario: Scenario): Promise<void> {
    setLabBusy(scenario.id);
    try {
      if (readOnly) setLabResult({ scenarioId: scenario.id, expected: scenario.expected, actual: scenario.actual ?? scenario.expected, matched: (scenario.actual ?? scenario.expected) === scenario.expected, summary: scenario.summary });
      else {
        const response = await fetch("/api/demo/run", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scenarioId: scenario.id }) });
        if (!response.ok) throw new Error("Scenario replay failed");
        setLabResult(await response.json() as ScenarioResult);
      }
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Scenario replay failed"); }
    finally { setLabBusy(""); }
  }

  if (error) return <main className="center"><section className="empty"><p className="eyebrow">CONNECTION ERROR</p><h1>Security data is unavailable</h1><p>{error}. Start the localhost API and refresh.</p></section></main>;
  if (!session) return <main className="center"><p className="loading">Loading verified session…</p></main>;

  return <div className="shell">
    <aside>
      <div className="brand"><div className="mark">W</div><div><strong>MCP Warden</strong><span>Security console</span></div></div>
      <nav aria-label="Primary"><a className="active" href="#overview">Overview</a><a href="#timeline">Session timeline</a><a href="#attack-lab">Attack Lab</a><a href="#policy">Policy</a><a href="#reports">Reports</a></nav>
      <div className="connection"><i></i><span>Local enforcement online</span><small>127.0.0.1 only</small></div>
    </aside>
    <main>
      <header><div><p className="eyebrow">PROTECTED SESSION</p><h1>Runtime overview</h1><p className="subtitle">{readOnly ? session.staticLabel : "One target. Every call inspected before execution."}</p></div><div className="header-actions"><span className="badge">{readOnly ? "READ-ONLY SNAPSHOT" : session.label}</span><span className="mode">{session.mode}</span></div></header>
      <section className="metrics" id="overview">
        <Metric label="Tool calls" value={session.metrics.totalToolCalls} note={`${session.targetName} target`} />
        <Metric label="Deterministic" value={`${Math.round(session.metrics.deterministicResolutionRate * 100)}%`} note="Resolved without GPT" />
        <Metric label="Blocked" value={session.metrics.blocks} note="Stopped pre-execution" />
        <Metric label="Judge tokens" value={session.metrics.judgeTokens} note="Recorded replay uses zero" />
      </section>
      {latestCritical && <section className="alert"><span className="risk-dot critical"></span><div><p className="eyebrow">LATEST CRITICAL EVENT</p><strong>{latestCritical.summary}</strong></div><button onClick={() => setSelected(latestCritical)}>Inspect event</button></section>}
      <section className="attack-lab panel" id="attack-lab">
        <div className="panel-head"><div><p className="eyebrow">ATTACK LAB</p><h2>{readOnly ? "Recorded scenario explorer" : "Offline fixture replay"}</h2></div><span className="badge">{scenarios.length} SCENARIOS</span></div>
        <div className="lab-grid"><div className="scenario-list">{scenarios.map((scenario) => <button key={scenario.id} disabled={labBusy.length > 0} onClick={() => void runScenario(scenario)}><span>{scenario.category}</span><strong>{scenario.title}</strong><small>Expected: {scenario.expected}{labBusy === scenario.id ? " · running…" : ""}</small></button>)}</div>
          <div className="lab-result">{labResult ? <><p className="eyebrow">ACTUAL RESULT</p><strong className={labResult.matched ? "matched" : "mismatch"}>{labResult.actual}</strong><p>{labResult.summary}</p><small>Expected {labResult.expected} · {labResult.matched ? "matched" : "mismatch"}</small></> : <><p className="eyebrow">EXPECTED BEFORE EXECUTION</p><h3>Select a controlled scenario</h3><p>The expected result is shown on every card. The recorded or local actual result appears here afterward.</p></>}</div></div>
      </section>
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
      <section className="policy-panel panel" id="policy">
        <div className="panel-head"><div><p className="eyebrow">POLICY DETAIL</p><h2>Active enforcement boundaries</h2></div><span className={`decision ${policy?.valid ? "allow" : "ask_user"}`}>{policy?.valid ? "VALID" : "UNAVAILABLE"}</span></div>
        <div className="policy-body"><div><label>Runtime mode<strong>{policy?.mode ?? session.mode}</strong></label><label>Output firewall<strong>Secrets redacted · injections quarantined</strong></label><label>Audit storage<strong>Redacted JSONL · SHA-256 hash chain</strong></label><label>Remediation<strong>Read-only proposal · explicit apply</strong></label></div><pre>{policy?.yaml ?? "Policy source is not exposed in this fixture-only view."}</pre></div>
      </section>
      <section className="downloads panel" id="reports"><div className="panel-head"><div><p className="eyebrow">VERIFIED ARTIFACTS</p><h2>Download reports</h2></div></div><div>{[
        ["Markdown report", readOnly ? snapshotUrl("report.md") : `/api/sessions/${session.sessionId}/report?format=markdown`],
        ["JSON report", readOnly ? snapshotUrl("report.json") : `/api/sessions/${session.sessionId}/report?format=json`],
        ["Redacted audit JSONL", readOnly ? snapshotUrl("audit.jsonl") : `/api/sessions/${session.sessionId}/audit`],
        ["Evaluation summary", readOnly ? snapshotUrl("evaluation-summary.json") : "/api/evaluation"]
      ].map(([label, href]) => <a key={label} href={href} download>{label}<span>↓</span></a>)}</div></section>
      <footer><span>MCP Warden v0.1.0</span><span>Dashboard is outside the enforcement path</span></footer>
    </main>
  </div>;
}

const rootElement = document.getElementById("root");
if (!rootElement) throw new Error("Dashboard root element is missing");
createRoot(rootElement).render(<StrictMode><App /></StrictMode>);
