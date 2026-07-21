import { StrictMode, useEffect, useMemo, useState, type MouseEvent } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource/josefin-sans/400.css";
import "@fontsource/josefin-sans/500.css";
import "@fontsource/josefin-sans/600.css";
import "@fontsource/josefin-sans/700.css";
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
  sourceState?: "LIVE_HEALTHY" | "LIVE_PARTIAL" | "LIVE_STALE" | "LIVE_INVALID" | "LIVE_CLOSED" | "RECORDED_SNAPSHOT";
  reasonCode?: string;
};
type SessionSummary = Pick<Session, "sessionId" | "label" | "sourceState" | "reasonCode">;
type PolicyDetail = { yaml: string; valid: boolean; mode: string };
type Scenario = { id: string; title: string; category: string; expected: string; actual?: string; summary: string };
type ScenarioResult = { scenarioId: string; expected: string; actual: string; matched: boolean; summary: string };
type IconName = "activity" | "download" | "flask" | "overview" | "policy" | "shield" | "timeline";
type View = "landing" | "console";

const consoleHashes = new Set(["#console", "#overview", "#timeline", "#attack-lab", "#policy", "#reports"]);

function snapshotUrl(file: string): string {
  return new URL(`snapshot/${file}`, document.baseURI).toString();
}

function isStaticPagesDeployment(): boolean {
  return window.location.hostname.endsWith(".github.io");
}

function apiTokenFromFragment(): string | undefined {
  const token = new URLSearchParams(window.location.hash.slice(1)).get("token");
  if (token === null) return undefined;
  window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
  return token;
}

function apiFetch(url: string, token: string | undefined, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);
  if (token !== undefined) headers.set("Authorization", `Bearer ${token}`);
  return fetch(url, { ...init, headers });
}

function sessionFromSnapshot(value: Session): Session { return value; }

function Icon({ name }: { name: IconName }) {
  const common = { fill: "none", stroke: "currentColor", strokeLinecap: "round" as const, strokeLinejoin: "round" as const, strokeWidth: 1.8 };
  if (name === "shield") return <svg viewBox="0 0 24 24" aria-hidden="true" {...common}><path d="M12 3 19 6v5c0 4.4-2.9 8.2-7 10-4.1-1.8-7-5.6-7-10V6l7-3Z" /><path d="m9 12 2 2 4-4" /></svg>;
  if (name === "overview") return <svg viewBox="0 0 24 24" aria-hidden="true" {...common}><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></svg>;
  if (name === "timeline") return <svg viewBox="0 0 24 24" aria-hidden="true" {...common}><path d="M4 6h16M4 12h10M4 18h16" /><circle cx="17" cy="12" r="2" /></svg>;
  if (name === "flask") return <svg viewBox="0 0 24 24" aria-hidden="true" {...common}><path d="M9 3h6M10 3v6l-5.6 8.1A2.5 2.5 0 0 0 6.5 21h11a2.5 2.5 0 0 0 2.1-3.9L14 9V3" /><path d="M8 15h8" /></svg>;
  if (name === "policy") return <svg viewBox="0 0 24 24" aria-hidden="true" {...common}><path d="M7 3h8l3 3v15H7z" /><path d="M15 3v4h4M10 12h5M10 16h5" /></svg>;
  if (name === "download") return <svg viewBox="0 0 24 24" aria-hidden="true" {...common}><path d="M12 3v12M8 11l4 4 4-4M5 21h14" /></svg>;
  return <svg viewBox="0 0 24 24" aria-hidden="true" {...common}><path d="M4 12h3l2-6 4 12 2-6h5" /></svg>;
}

function Metric({ icon, label, note, tone, value }: { icon: IconName; label: string; value: string | number; note: string; tone: string }) {
  return <article className={`metric ${tone}`}>
    <span className="metric-icon"><Icon name={icon} /></span>
    <div><span className="metric-label">{label}</span><strong>{value}</strong><small>{note}</small></div>
  </article>;
}

function Landing({ onOpenConsole }: { onOpenConsole: () => void }) {
  return <main className="landing" id="top">
    <header className="landing-header">
      <a className="brand landing-brand" href="#top" aria-label="ToolBastion home"><div className="mark"><Icon name="shield" /></div><div><strong>ToolBastion</strong><span>MCP security gateway</span></div></a>
      <nav className="landing-nav" aria-label="Product navigation">
        <a href="#boundary">The boundary</a>
        <a href="#how-it-works">How it works</a>
        <a href="#proof">Evidence</a>
      </nav>
      <button className="header-console-button" type="button" onClick={onOpenConsole}>Open security console</button>
    </header>

    <section className="landing-hero" aria-labelledby="landing-title">
      <div className="landing-copy">
        <p className="eyebrow">THE EXECUTION FIREWALL FOR MCP</p>
        <h1 id="landing-title">Make every MCP action<br /><span>earn execution.</span></h1>
        <p className="landing-lede">ToolBastion turns an AI tool call into a verifiable decision. It validates the request, stops deterministic threats, confines the target, and records redacted audit evidence.</p>
        <div className="landing-actions">
          <button className="primary-action" type="button" onClick={onOpenConsole}>Inspect a decision <span aria-hidden="true">→</span></button>
          <a className="secondary-action" href="#boundary">See the boundary</a>
        </div>
        <ul className="trust-points" aria-label="Core security capabilities">
          <li><span><Icon name="shield" /></span>Pre-execution enforcement</li>
          <li><span><Icon name="policy" /></span>Bounded tool access</li>
          <li><span><Icon name="timeline" /></span>Inspectable audit records</li>
        </ul>
      </div>
      <div className="landing-visual" aria-label="Every MCP tool call passes through ToolBastion before reaching its target">
        <div className="visual-grid"></div>
        <div className="visual-caption"><span className="live-dot"></span> Decision path</div>
        <div className="flow-node agent-node"><small>01</small><strong>AI agent</strong><span>Tool call request</span></div>
        <div className="flow-line flow-line-one"></div>
        <div className="flow-node bastion-node"><div className="mini-mark"><Icon name="shield" /></div><small>02</small><strong>ToolBastion</strong><span>Inspect, decide, record</span></div>
        <div className="security-layers"><span>Policy</span><span>Trust</span><span>Output</span><span>Audit</span></div>
        <div className="flow-line flow-line-two"></div>
        <div className="flow-node target-node"><small>03</small><strong>MCP target</strong><span>Only safe execution</span></div>
        <div className="decision-receipt" aria-hidden="true"><span>Decision receipt</span><strong>Policy checked</strong><small>redacted · tamper-evident</small></div>
        <p className="visual-note">A target can only receive a call after the gateway produces an allow decision.</p>
      </div>
    </section>

    <section className="landing-section how-it-works" id="how-it-works" aria-labelledby="how-it-works-title">
      <div><p className="eyebrow">THE CONTROL LOOP</p><h2 id="how-it-works-title">Not a dashboard. A decision system.</h2></div>
      <div className="stage-grid">
        <article><span>01</span><h3>Validate</h3><p>Tool schemas, arguments, metadata, and configuration are treated as untrusted input.</p></article>
        <article><span>02</span><h3>Gate</h3><p>Deterministic rules stop known-dangerous requests before a model or target can act.</p></article>
        <article><span>03</span><h3>Contain</h3><p>Containerized targets can run without network access and with a reduced execution surface.</p></article>
        <article><span>04</span><h3>Receipt</h3><p>Redacted, tamper-evident audit artifacts preserve the reason behind every decision.</p></article>
      </div>
    </section>

    <section className="proof-section" id="proof" aria-labelledby="proof-title">
      <div className="proof-copy"><p className="eyebrow">VERIFIABLE, NOT THEATRICAL</p><h2 id="proof-title">Every decision leaves an audit record.</h2><p>The console exposes local runtime evidence when available and clearly labels static snapshots when it is not. The enforcement path itself runs independently from this interface.</p><a href="#boundary">Explore the decision path <span aria-hidden="true">→</span></a></div>
      <div className="proof-cards">
        <article><span className="proof-icon"><Icon name="shield" /></span><p>Hard deny</p><strong>Before execution</strong><small>Deterministic blocks cannot be overridden by a model.</small></article>
        <article><span className="proof-icon"><Icon name="activity" /></span><p>Target isolation</p><strong>No default egress</strong><small>Containerized targets can run without a network path.</small></article>
        <article><span className="proof-icon"><Icon name="timeline" /></span><p>Audit evidence</p><strong>Secrets redacted</strong><small>Reports preserve decisions without persisting raw credentials.</small></article>
      </div>
    </section>

    <section className="boundary-section" id="boundary" aria-labelledby="boundary-title">
      <div className="boundary-copy"><p className="eyebrow">THE BASTION DIFFERENCE</p><h2 id="boundary-title">Audit evidence, not security theater.</h2><p>A raw tool request is not trusted because it came from an agent. ToolBastion captures the intent, applies layered controls, and records why the target did—or did not—receive the call.</p><button className="primary-action boundary-console-button" type="button" onClick={onOpenConsole}>Inspect the security console <span aria-hidden="true">→</span></button></div>
      <div className="receipt-board" aria-label="A sample ToolBastion decision receipt">
        <div className="receipt-board-head"><span className="live-dot"></span><span>Decision receipt</span><small>event chain intact</small></div>
        <div className="receipt-steps">
          <article className="receipt-step intent-step"><span>01 · Incoming intent</span><strong>filesystem.write</strong><p>Arguments normalized and inspected as untrusted input.</p><small>REQUEST FINGERPRINTED</small></article>
          <article className="receipt-step decision-step"><span>02 · Policy verdict</span><strong>BLOCKED</strong><p>Deterministic hard deny matched before target execution.</p><small>RULE: PATH_TRAVERSAL</small></article>
          <article className="receipt-step evidence-step"><span>03 · Evidence</span><strong>Redacted record</strong><p>Decision, reason, and integrity data are retained for review.</p><small>AUDIT TRAIL SEALED</small></article>
        </div>
      </div>
    </section>

    <footer className="landing-footer"><span>ToolBastion v0.1.4</span><span>Enforcement runs independently from this interface.</span><a href="https://github.com/MaharMuavia/toolbastion" target="_blank" rel="noreferrer">View source</a></footer>
  </main>;
}

function App() {
  const [view, setView] = useState<View>(() => consoleHashes.has(window.location.hash) || window.location.hash.includes("token=") ? "console" : "landing");
  const [apiToken] = useState(apiTokenFromFragment);
  const [session, setSession] = useState<Session | null>(null);
  const [selected, setSelected] = useState<Event | null>(null);
  const [liveError, setLiveError] = useState("");
  const [downloadError, setDownloadError] = useState("");
  const [policy, setPolicy] = useState<PolicyDetail | null>(null);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [labResult, setLabResult] = useState<ScenarioResult | null>(null);
  const [labBusy, setLabBusy] = useState("");
  const [readOnly, setReadOnly] = useState(false);

  const openConsole = () => {
    window.location.hash = "console";
    setView("console");
    window.scrollTo({ top: 0, behavior: "smooth" });
  };
  const openLanding = () => {
    window.history.pushState(null, "", `${window.location.pathname}${window.location.search}`);
    setView("landing");
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const openSnapshot = async () => {
    try {
      const response = await fetch(snapshotUrl("session.json"));
      if (!response.ok) throw new Error("Recorded snapshot unavailable");
      const value = sessionFromSnapshot(await response.json() as Session);
      setReadOnly(true);
      setLiveError("");
      setSession(value);
      setSelected(value.events.at(-1) ?? null);
    } catch (reason) {
      setLiveError(reason instanceof Error ? reason.message : "Recorded snapshot unavailable");
    }
  };

  useEffect(() => {
    const syncView = () => setView(consoleHashes.has(window.location.hash) ? "console" : "landing");
    window.addEventListener("hashchange", syncView);
    window.addEventListener("popstate", syncView);
    return () => {
      window.removeEventListener("hashchange", syncView);
      window.removeEventListener("popstate", syncView);
    };
  }, []);
  useEffect(() => { document.title = view === "console" ? "ToolBastion Security Console" : "ToolBastion | Secure MCP tooling"; }, [view]);
  useEffect(() => {
    if (view !== "console") return;
    if (isStaticPagesDeployment()) {
      void openSnapshot();
      return;
    }
    let mounted = true;
    const load = async () => {
      try {
        const listResponse = await apiFetch("/api/sessions", apiToken);
        if (listResponse.status === 401) throw new Error("Authentication failed");
        if (!listResponse.ok) throw new Error("Live runtime unavailable");
        const summaries = await listResponse.json() as SessionSummary[];
        const active = summaries[0];
        if (!active) throw new Error("No enforcement session is available");
        const response = await apiFetch(`/api/sessions/${encodeURIComponent(active.sessionId)}`, apiToken);
        if (response.status === 401) throw new Error("Authentication failed");
        if (!response.ok) throw new Error("No live session is available");
        const value = await response.json() as Session;
        if (mounted) { setReadOnly(false); setLiveError(""); setSession(value); setSelected(value.events.at(-1) ?? null); }
      } catch (reason) {
        if (mounted) setLiveError(reason instanceof Error ? reason.message : "Live runtime unavailable");
      }
    };
    void load();
    return () => { mounted = false; };
  }, [apiToken, view]);
  useEffect(() => {
    if (view !== "console" || !session || session.label !== "LIVE LOCAL SESSION") return;
    const refresh = async () => {
      try {
        const response = await apiFetch(`/api/sessions/${encodeURIComponent(session.sessionId)}`, apiToken);
        if (!response.ok) return;
        const next = await response.json() as Session;
        setSession(next);
        setSelected((current) => current ? next.events.find((event) => event.eventId === current.eventId) ?? next.events.at(-1) ?? null : next.events.at(-1) ?? null);
      } catch { /* Preserve the last verified live state during a transient refresh failure. */ }
    };
    const timer = window.setInterval(() => { void refresh(); }, 1_000);
    return () => window.clearInterval(timer);
  }, [apiToken, session?.label, session?.sessionId, view]);
  useEffect(() => {
    if (view !== "console") return;
    apiFetch("/api/policy", apiToken).then((response) => response.ok ? response.json() as Promise<PolicyDetail> : null).then(setPolicy).catch(() => setPolicy(null));
  }, [apiToken, view]);
  useEffect(() => {
    if (view !== "console") return;
    apiFetch("/api/demo/scenarios", apiToken).then(async (response) => { if (!response.ok) throw new Error(); return response.json() as Promise<Scenario[]>; }).then(setScenarios)
      .catch(() => { fetch(snapshotUrl("scenarios.json")).then((response) => response.json() as Promise<Scenario[]>).then(setScenarios).catch(() => setScenarios([])); });
  }, [apiToken, view]);
  const latestCritical = useMemo<Event | undefined>(() => session?.events.filter((event) => event.riskLevel === "critical").at(-1), [session]);

  async function runScenario(scenario: Scenario): Promise<void> {
    setLabBusy(scenario.id);
    try {
      if (readOnly) setLabResult({ scenarioId: scenario.id, expected: scenario.expected, actual: scenario.actual ?? "UNAVAILABLE", matched: scenario.actual === scenario.expected, summary: scenario.actual === undefined ? "Recorded evidence is missing." : scenario.summary });
      else {
        const response = await apiFetch("/api/demo/run", apiToken, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scenarioId: scenario.id }) });
        if (!response.ok) throw new Error("Scenario replay failed");
        setLabResult(await response.json() as ScenarioResult);
      }
    } catch (reason) { setDownloadError(reason instanceof Error ? reason.message : "Scenario replay failed"); }
    finally { setLabBusy(""); }
  }

  async function downloadArtifact(event: MouseEvent<HTMLAnchorElement>, href: string): Promise<void> {
    if (apiToken === undefined || readOnly) return;
    event.preventDefault();
    try {
      const response = await apiFetch(href, apiToken);
      if (!response.ok) throw new Error("Report download failed");
      const objectUrl = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = objectUrl;
      link.download = href.includes("audit") ? "toolbastion-audit.jsonl" : href.includes("evaluation") ? "toolbastion-evaluation-summary.json" : href.includes("format=json") ? "toolbastion-report.json" : "toolbastion-report.md";
      link.click();
      URL.revokeObjectURL(objectUrl);
    } catch (reason) { setDownloadError(reason instanceof Error ? reason.message : "Report download failed"); }
  }

  if (view === "landing") return <Landing onOpenConsole={openConsole} />;
  if (liveError && !readOnly) return <main className="center"><section className="empty" aria-live="polite"><p className="eyebrow">LIVE RUNTIME UNAVAILABLE</p><h1>{liveError === "Authentication failed" ? "Authentication failed" : "Live runtime unavailable"}</h1><p>Reason: {liveError}</p><button className="text-action" type="button" onClick={() => { setLiveError(""); setSession(null); }}>Retry live connection</button><button className="text-action" type="button" onClick={() => void openSnapshot()}>Open verified recorded snapshot</button><button className="text-action" type="button" onClick={openLanding}>Back to product overview</button></section></main>;
  if (!session) return <main className="center"><p className="loading">Loading verified session…</p></main>;

  const recorded = readOnly || (session.sourceState !== "LIVE_HEALTHY" && session.sourceState !== "LIVE_PARTIAL") || session.label === "OFFLINE FIXTURE REPLAY";
  const sourceState = readOnly ? "RECORDED_SNAPSHOT" : session.sourceState ?? "RECORDED_SNAPSHOT";

  return <div className="shell">
    <aside className="sidebar">
      <div>
        <div className="brand"><div className="mark"><Icon name="shield" /></div><div><strong>ToolBastion</strong><span>Security console</span></div></div>
        <p className="sidebar-kicker">Runtime security</p>
        <nav aria-label="Primary">
          <a className="active" href="#overview"><Icon name="overview" /><span>Overview</span></a>
          <a href="#timeline"><Icon name="timeline" /><span>Session timeline</span></a>
          <a href="#attack-lab"><Icon name="flask" /><span>Attack Lab</span></a>
          <a href="#policy"><Icon name="policy" /><span>Policy</span></a>
          <a href="#reports"><Icon name="download" /><span>Reports</span></a>
        </nav>
      </div>
      <div className="sidebar-bottom">
        <div className={`connection ${recorded ? "recorded" : ""}`}><i></i><span>{recorded ? "Recorded enforcement session" : "Local enforcement online"}</span><small>{recorded ? "Verified fixture · no live target" : "127.0.0.1 only"}</small></div>
        <p>Enforcement runs independently from this dashboard.</p>
      </div>
    </aside>
    <main className="dashboard-main">
      {downloadError && <p className="alert" role="status">{downloadError}</p>}
      <header className="dashboard-header"><div><p className="eyebrow">PROTECTED SESSION</p><h1>Runtime overview</h1><p className="subtitle">{recorded ? session.staticLabel ?? "Verified recorded evidence. No live target is connected." : "One target. Every call inspected before execution."}</p></div><div className="header-actions"><button className="dashboard-return" type="button" onClick={openLanding}>Product overview</button><span className="badge">{readOnly ? "READ-ONLY SNAPSHOT" : session.label}</span><span className="mode"><Icon name="activity" />{session.mode}</span></div></header>
      {sourceState === "LIVE_PARTIAL" && <section className="alert" aria-live="polite"><span className="risk-dot high"></span><div><p className="eyebrow">LIVE EVIDENCE · BOUNDED RETENTION</p><strong>Earlier dashboard lifecycle entries were rotated. Download the verified audit log for complete session evidence.</strong></div></section>}
      {sourceState !== "LIVE_HEALTHY" && sourceState !== "LIVE_PARTIAL" && <section className="alert" aria-live="polite"><span className="risk-dot high"></span><div><p className="eyebrow">NOT LIVE EVIDENCE</p><strong>{sourceState.replaceAll("_", " ")} · {session.reasonCode?.replaceAll("_", " ") ?? "recorded snapshot selected"}</strong></div></section>}
      <section className="metrics" id="overview">
        <Metric icon="activity" tone="blue" label="Tool calls" value={session.metrics.totalToolCalls} note={`${session.targetName} target`} />
        <Metric icon="overview" tone="mint" label="Deterministic" value={`${Math.round(session.metrics.deterministicResolutionRate * 100)}%`} note="Resolved without GPT" />
        <Metric icon="shield" tone="amber" label="Blocked" value={session.metrics.blocks} note="Stopped pre-execution" />
        <Metric icon="flask" tone="violet" label="Judge tokens" value={session.metrics.judgeTokens} note={recorded ? "Recorded replay usage" : "Current live session"} />
      </section>
      {latestCritical && <section className="alert"><span className="risk-dot critical"></span><div><p className="eyebrow">LATEST CRITICAL EVENT</p><strong>{latestCritical.summary}</strong></div><button onClick={() => setSelected(latestCritical)}>Inspect event</button></section>}
      <section className="attack-lab panel" id="attack-lab">
        <div className="panel-head"><div><p className="eyebrow">ATTACK LAB</p><h2>Recorded scenario explorer</h2></div><span className="badge">{scenarios.length} FIXTURES</span></div>
        <div className="lab-grid"><div className="scenario-list">{scenarios.map((scenario) => <button key={scenario.id} className={labResult?.scenarioId === scenario.id ? "selected" : ""} disabled={labBusy.length > 0} aria-pressed={labResult?.scenarioId === scenario.id} onClick={() => void runScenario(scenario)}><span>{scenario.category}</span><strong>{scenario.title}</strong><small>Expected: {scenario.expected}{labBusy === scenario.id ? " · running…" : ""}</small></button>)}</div>
          <div className="lab-result">{labResult ? <><p className="eyebrow">ACTUAL RESULT</p><strong className={labResult.matched ? "matched" : "mismatch"}>{labResult.actual}</strong><p>{labResult.summary}</p><small>Expected {labResult.expected} · {labResult.matched ? "matched" : "mismatch"}</small></> : <><p className="eyebrow">EXPECTED BEFORE EXECUTION</p><h3>Select a controlled scenario</h3><p>The expected result is shown on every card. The recorded or local actual result appears here afterward.</p></>}</div></div>
      </section>
      <section className="workspace" id="timeline">
        <div className="panel timeline"><div className="panel-head"><div><p className="eyebrow">SESSION TIMELINE</p><h2>Enforcement activity</h2></div><code>{session.sessionId}</code></div>
          <div className="events">{session.events.map((event) => <button key={event.eventId} className={`event ${selected?.eventId === event.eventId ? "selected" : ""}`} onClick={() => setSelected(event)}>
            <span className={`risk-dot ${event.riskLevel}`}></span><span className="event-time">{new Date(event.timestamp).toLocaleTimeString([], { hour12: false })}</span><span className="event-copy"><strong>{event.toolName ?? event.eventType}</strong><small>{event.summary}</small></span>{event.decision && <span className={`decision ${event.decision.toLowerCase()}`}>{event.decision}</span>}<span className="latency">{event.latencyMs} ms</span>
          </button>)}</div>
        </div>
        <div className="panel detail"><div className="panel-head"><div><p className="eyebrow">EVENT INSPECTOR</p><h2>{selected?.eventType ?? "Select an event"}</h2></div></div>
          {selected && <div className="detail-body"><div className="detail-grid"><label>Risk<strong className={selected.riskLevel}>{selected.riskLevel}</strong></label><label>Decision<strong>{selected.decision ?? "—"}</strong></label><label>Latency<strong>{selected.latencyMs} ms</strong></label><label>Judge tokens<strong>{selected.judgeTokens}</strong></label></div><h3>Evidence summary</h3><p>{selected.summary}</p><h3>Audit identity</h3><code>{selected.eventId}</code><div className="chain"><i></i> {recorded ? "Recorded fixture event" : "Redacted live lifecycle event"} · raw secrets unavailable</div></div>}
        </div>
      </section>
      <section className="policy-panel panel" id="policy">
        <div className="panel-head"><div><p className="eyebrow">POLICY DETAIL</p><h2>Active enforcement boundaries</h2></div><span className={`decision ${policy?.valid ? "allow" : "ask_user"}`}>{policy?.valid ? "VALID" : "UNAVAILABLE"}</span></div>
        <div className="policy-body"><div><label>Runtime mode<strong>{policy?.mode ?? session.mode}</strong></label><label>Output firewall<strong>Secrets redacted · injections quarantined</strong></label><label>Audit storage<strong>Redacted JSONL · sealed SHA-256 chain</strong></label><label>Remediation<strong>Structured exact-host proposal · explicit apply</strong></label></div><pre>{policy?.yaml ?? "Policy source is not exposed in this fixture-only view."}</pre></div>
      </section>
      <section className="downloads panel" id="reports"><div className="panel-head"><div><p className="eyebrow">VERIFIED ARTIFACTS</p><h2>Download reports</h2></div></div><div>{[
        ["Markdown report", readOnly ? snapshotUrl("report.md") : `/api/sessions/${session.sessionId}/report?format=markdown`],
        ["JSON report", readOnly ? snapshotUrl("report.json") : `/api/sessions/${session.sessionId}/report?format=json`],
        ["Redacted audit JSONL", readOnly ? snapshotUrl("audit.jsonl") : `/api/sessions/${session.sessionId}/audit`],
        ["Evaluation summary", readOnly ? snapshotUrl("evaluation-summary.json") : "/api/evaluation"]
      ].map(([label, href]) => <a key={label} href={href} download onClick={(event) => void downloadArtifact(event, href!)}>{label}<span><Icon name="download" /></span></a>)}</div></section>
      <footer><span>ToolBastion v0.1.4</span><span>Dashboard is outside the enforcement path</span></footer>
    </main>
  </div>;
}

const rootElement = document.getElementById("root");
if (!rootElement) throw new Error("Dashboard root element is missing");
createRoot(rootElement).render(<StrictMode><App /></StrictMode>);
