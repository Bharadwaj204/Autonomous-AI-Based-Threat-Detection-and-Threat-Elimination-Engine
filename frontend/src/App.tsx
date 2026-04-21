import {
  useEffect, useState, useRef, useCallback
} from 'react';
import {
  AreaChart, Area, Line,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts';
import './index.css';

// ─── Types ───────────────────────────────────────────────────────────────────
interface MonitorStatus {
  file: boolean;
  network: boolean;
  process: boolean;
  ml_engine: boolean;
  response: boolean;
  forensics: boolean;
}

interface Metrics {
  cpu_usage: number;
  memory_usage: number;
  entropy: number;
  packet_rate: number;
  bytes_per_sec: number;
  connection_count: number;
}

interface ChartPoint extends Partial<Metrics> { time: string; }

interface SecurityEvent {
  id: number;
  timestamp: string;
  type: string;
  message: string;
  severity: 'info' | 'warning' | 'high' | 'critical' | 'error';
  data: Record<string, unknown>;
}

interface ThreatRecord {
  id: number;
  timestamp: string;
  type: string;
  severity: string;
  method: string;
  confidence: number;
  reason: string;
  mitigated: number;
}

interface IOC {
  id: number;
  type: string;
  value: string;
  source: string;
  confidence: number;
  created_at: string;
}

interface ForensicEntry {
  seq: number;
  timestamp: string;
  event_type: string;
  severity: string;
  hash: string;
  data: Record<string, unknown>;
}

// ─── Constants ───────────────────────────────────────────────────────────────
const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const WS_URL = API.replace(/^http/, 'ws') + '/ws';
const MAX_PTS = 40;

type Tab = 'dashboard' | 'threats' | 'intel' | 'forensics' | 'demo';

// ─── Helpers ─────────────────────────────────────────────────────────────────


const SEV_ICON: Record<string, string> = {
  critical: '🔴', high: '🟠', warning: '🟡', info: '🔵', error: '⛔'
};

const fmtTime = (ts: string) => {
  try { return new Date(ts).toLocaleTimeString(); } catch { return ts; }
};

const fmtDate = (ts: string) => {
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
};

// ─── Sub-components ───────────────────────────────────────────────────────────
function MetricBar({
  label, value, max, color, unit
}: { label: string; value: number; max: number; color: string; unit?: string }) {
  const pct = Math.min((value / max) * 100, 100);
  return (
    <div className="metric-row">
      <div className="metric-header">
        <span className="metric-name">{label}</span>
        <span className="metric-val" style={{ color }}>
          {value.toFixed(value < 10 ? 3 : 1)}{unit ?? ''}
        </span>
      </div>
      <div className="metric-bar">
        <div className="metric-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  );
}

function SeverityBadge({ sev }: { sev: string }) {
  return (
    <span className={`severity-badge ${sev}`}>
      {SEV_ICON[sev] ?? '◾'} {sev}
    </span>
  );
}

// ─── App ─────────────────────────────────────────────────────────────────────
export default function App() {
  const [tab, setTab] = useState<Tab>('dashboard');
  const [connected, setConnected] = useState(false);
  const [monitors, setMonitors] = useState<MonitorStatus>({
    file: false, network: false, process: false,
    ml_engine: false, response: false, forensics: false
  });
  const [metrics, setMetrics] = useState<Metrics>({
    cpu_usage: 0, memory_usage: 0, entropy: 0,
    packet_rate: 0, bytes_per_sec: 0, connection_count: 0
  });
  const [chart, setChart] = useState<ChartPoint[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [threatCount, setThreatCount] = useState(0);

  // Tab-specific data
  const [threats, setThreats] = useState<ThreatRecord[]>([]);
  const [dbStats, setDbStats] = useState<Record<string, unknown>>({});
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [forensicEntries, setForensicEntries] = useState<ForensicEntry[]>([]);
  const [chainOk, setChainOk] = useState<boolean | null>(null);
  const [demoResult, setDemoResult] = useState<Record<string, unknown> | null>(null);
  const [demoBusy, setDemoBusy] = useState(false);
  const [testBusy, setTestBusy] = useState(false);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnect = useRef<ReturnType<typeof setTimeout> | null>(null);

  // ── WebSocket ─────────────────────────────────────────────────────────────
  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      if (reconnect.current) clearTimeout(reconnect.current);
    };
    ws.onclose = () => {
      setConnected(false);
      reconnect.current = setTimeout(connect, 4000);
    };
    ws.onerror = () => ws.close();
    ws.onmessage = ({ data }: MessageEvent) => {
      if (data === 'pong') return;
      try {
        const msg = JSON.parse(data as string);
        switch (msg.type) {
          case 'init':
            setEvents(msg.data.events ?? msg.data.logs ?? []);
            setMonitors(msg.data.monitors ?? {});
            setThreatCount(msg.data.threat_count ?? 0);
            break;
          case 'metrics': {
            const m: Metrics = msg.data;
            setMetrics(m);
            if (msg.monitors) setMonitors(msg.monitors);
            if (msg.threat_count !== undefined) setThreatCount(msg.threat_count);
            const now = new Date().toLocaleTimeString('en-GB', { hour12: false });
            setChart(prev => {
              const next = [...prev, { ...m, time: now }];
              return next.length > MAX_PTS ? next.slice(-MAX_PTS) : next;
            });
            break;
          }
          case 'threat_alert':
          case 'action': {
            const ev: SecurityEvent = msg.data;
            setEvents(prev => [ev, ...prev].slice(0, 200));
            if (msg.type === 'threat_alert') setThreatCount(p => p + 1);
            break;
          }
        }
      } catch { /* ignore */ }
    };
    const ping = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send('ping');
    }, 25000);
    ws.addEventListener('close', () => clearInterval(ping));
  }, []);

  useEffect(() => {
    connect();
    return () => {
      wsRef.current?.close();
      if (reconnect.current) clearTimeout(reconnect.current);
    };
  }, [connect]);

  // ── Tab data fetching ──────────────────────────────────────────────────────
  useEffect(() => {
    if (tab === 'threats') fetchThreats();
    if (tab === 'intel')   fetchIntel();
    if (tab === 'forensics') fetchForensics();
  }, [tab]);

  const fetchThreats = async () => {
    try {
      const r = await fetch(`${API}/api/threats`);
      const d = await r.json();
      setThreats(d.threats ?? []);
      setDbStats(d.stats ?? {});
    } catch { /* ignore */ }
  };

  const fetchIntel = async () => {
    try {
      const r = await fetch(`${API}/api/intel`);
      const d = await r.json();
      setIocs(d.iocs ?? []);
    } catch { /* ignore */ }
  };

  const fetchForensics = async () => {
    try {
      const r = await fetch(`${API}/api/forensics`);
      const d = await r.json();
      setForensicEntries(d.entries ?? []);
      setChainOk(d.chain_integrity?.valid ?? null);
    } catch { /* ignore */ }
  };

  // ── Actions ────────────────────────────────────────────────────────────────
  const triggerTest = async () => {
    setTestBusy(true);
    try {
      await fetch(`${API}/api/response/test`, { method: 'POST' });
    } catch { /* ignore */ } finally {
      setTimeout(() => setTestBusy(false), 2000);
    }
  };

  const triggerDemo = async () => {
    setDemoBusy(true);
    setDemoResult(null);
    try {
      const r = await fetch(`${API}/api/demo/ransomware`, { method: 'POST' });
      const d = await r.json();
      setDemoResult(d);
    } catch (e) {
      setDemoResult({ status: 'error', message: String(e) });
    } finally {
      setTimeout(() => setDemoBusy(false), 2000);
    }
  };

  // ── Render ─────────────────────────────────────────────────────────────────
  const tabs: { id: Tab; label: string; icon: string }[] = [
    { id: 'dashboard',  label: 'Dashboard',   icon: '📊' },
    { id: 'threats',    label: 'Threats',      icon: '⚠️' },
    { id: 'intel',      label: 'Intel DB',     icon: '🔍' },
    { id: 'forensics',  label: 'Forensics',    icon: '🔐' },
    { id: 'demo',       label: 'Demo',         icon: '🧪' },
  ];

  return (
    <div className="app">
      {/* ── Header ──────────────────────────────────────────────────── */}
      <header className="header">
        <div className="header-brand">
          <div className="logo-icon">🛡</div>
          <div>
            <div className="brand-title">THREAT<span>SENTINEL</span></div>
            <div className="brand-sub">Autonomous AI Cybersecurity — v2.0</div>
          </div>
        </div>
        <nav className="tab-nav">
          {tabs.map(t => (
            <button
              key={t.id}
              className={`tab-btn ${tab === t.id ? 'active' : ''}`}
              onClick={() => setTab(t.id)}
            >
              {t.icon} {t.label}
            </button>
          ))}
        </nav>
        <div className="header-right">
          {threatCount > 0 && (
            <div className="threat-badge">⚠ {threatCount}</div>
          )}
          <div className={`connection-badge ${connected ? 'online' : 'offline'}`}>
            <div className={`dot ${connected ? 'online' : 'offline'}`} />
            {connected ? 'Live' : 'Offline'}
          </div>
          <button className="test-btn" onClick={triggerTest}
            disabled={testBusy || !connected}>
            {testBusy ? '⏳' : '🧪 Test'}
          </button>
        </div>
      </header>

      {/* ── Body ──────────────────────────────────────────────────────── */}
      <div className="body">

        {/* ════ DASHBOARD TAB ═══════════════════════════════════════════ */}
        {tab === 'dashboard' && (
          <div className="main">
            {/* Stats Row */}
            <div className="stats-row">
              {[
                { icon: '💻', label: 'CPU',        val: `${metrics.cpu_usage.toFixed(1)}%`,      color: 'blue'   },
                { icon: '🧠', label: 'Memory',      val: `${metrics.memory_usage.toFixed(1)}%`,   color: 'green'  },
                { icon: '⚡', label: 'Threats',     val: String(threatCount),                      color: 'red'    },
                { icon: '🌐', label: 'Connections', val: String(metrics.connection_count),          color: 'purple' },
              ].map(s => (
                <div key={s.label} className="stat-card">
                  <div className={`stat-icon ${s.color}`}>{s.icon}</div>
                  <div className="stat-info">
                    <div className="stat-label">{s.label}</div>
                    <div className={`stat-value ${s.color}`}>{s.val}</div>
                  </div>
                </div>
              ))}
            </div>

            {/* Sidebar + Content */}
            <aside className="sidebar">
              {/* Monitor Status */}
              <div className="panel">
                <div className="panel-header">⚙️ Module Status</div>
                <div className="monitor-list">
                  {(Object.entries(monitors) as [string, boolean][]).map(([k, v]) => (
                    <div key={k} className={`monitor-item ${v ? 'active' : 'offline'}`}>
                      <div className="monitor-name">{k.replace('_', ' ')}</div>
                      <span className={`monitor-badge ${v ? 'active' : 'offline'}`}>
                        {v ? 'ON' : 'OFF'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Live Metrics */}
              <div className="panel">
                <div className="panel-header">📡 Live Metrics</div>
                <div className="metrics-list">
                  <MetricBar label="Entropy"   value={metrics.entropy}       max={8}      color="#d29922" />
                  <MetricBar label="CPU"        value={metrics.cpu_usage}     max={100}    color="#58a6ff" unit="%" />
                  <MetricBar label="Memory"     value={metrics.memory_usage}  max={100}    color="#3fb950" unit="%" />
                  <MetricBar label="Pkt/s"      value={metrics.packet_rate}   max={5000}   color="#bc8cff" />
                  <MetricBar label="KB/s"       value={metrics.bytes_per_sec/1024} max={500} color="#e09b2a" />
                </div>
              </div>
            </aside>

            <div className="content">
              {/* Telemetry Chart */}
              <div className="panel chart-panel">
                <div className="panel-header">📈 Real-Time Telemetry</div>
                <div className="chart-wrapper">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={chart} margin={{ top: 4, right: 16, bottom: 0, left: -20 }}>
                      <defs>
                        {[
                          ['cpu', '#58a6ff'], ['mem', '#3fb950'],
                          ['ent', '#d29922']
                        ].map(([k, c]) => (
                          <linearGradient key={k} id={`g_${k}`} x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%"  stopColor={c} stopOpacity={0.3} />
                            <stop offset="95%" stopColor={c} stopOpacity={0}   />
                          </linearGradient>
                        ))}
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
                      <XAxis dataKey="time" stroke="#6e7681" tick={{ fontSize: 10 }} interval="preserveStartEnd" />
                      <YAxis stroke="#6e7681" tick={{ fontSize: 10 }} />
                      <Tooltip contentStyle={{ background:'#1c2128', border:'1px solid #30363d', borderRadius:8, fontSize:12 }} />
                      <Legend wrapperStyle={{ fontSize: 11, color: '#8b949e' }} />
                      <Area type="monotone" dataKey="cpu_usage"    name="CPU%"    stroke="#58a6ff" fill="url(#g_cpu)" strokeWidth={2} dot={false} isAnimationActive={false} />
                      <Area type="monotone" dataKey="memory_usage" name="Mem%"    stroke="#3fb950" fill="url(#g_mem)" strokeWidth={2} dot={false} isAnimationActive={false} />
                      <Area type="monotone" dataKey="entropy"      name="Entropy" stroke="#d29922" fill="url(#g_ent)" strokeWidth={2} dot={false} isAnimationActive={false} />
                      <Line type="monotone" dataKey="packet_rate"  name="Pkt/s"   stroke="#bc8cff" strokeWidth={1} dot={false} isAnimationActive={false} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Event Stream */}
              <div className="panel logs-panel">
                <div className="panel-header">
                  🛡 Security Event Stream
                  <span className="event-count">{events.length}</span>
                </div>
                <div className="logs-body">
                  {events.length === 0 ? (
                    <div className="empty-state">
                      <span style={{ fontSize: 28 }}>🔍</span>
                      Monitoring active — no events yet
                    </div>
                  ) : events.map(ev => (
                    <div key={ev.id} className={`log-entry ${ev.severity}`}>
                      <span className="log-time">{fmtTime(ev.timestamp)}</span>
                      <SeverityBadge sev={ev.severity} />
                      <span className="log-message">{ev.message}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ════ THREATS TAB ═════════════════════════════════════════════ */}
        {tab === 'threats' && (
          <div className="tab-content">
            {/* Stats */}
            <div className="stats-row mini">
              {[
                ['Total',     (dbStats as any).total_threats ?? 0, 'blue'],
                ['Active',    (dbStats as any).active ?? 0,        'red'],
                ['Mitigated', (dbStats as any).mitigated ?? 0,     'green'],
              ].map(([l, v, c]) => (
                <div key={String(l)} className="stat-card">
                  <div className="stat-info">
                    <div className="stat-label">{l}</div>
                    <div className={`stat-value ${c}`}>{v}</div>
                  </div>
                </div>
              ))}
              <button className="refresh-btn" onClick={fetchThreats}>🔄 Refresh</button>
            </div>

            <div className="panel">
              <div className="panel-header">⚠️ Threat Records (Persistent DB)</div>
              <div className="table-wrapper">
                {threats.length === 0 ? (
                  <div className="empty-state">No threats recorded yet</div>
                ) : (
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>ID</th><th>Time</th><th>Severity</th>
                        <th>Method</th><th>Confidence</th><th>Reason</th><th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {threats.map(t => (
                        <tr key={t.id}>
                          <td>#{t.id}</td>
                          <td>{fmtTime(t.timestamp)}</td>
                          <td><SeverityBadge sev={t.severity} /></td>
                          <td><span className="method-badge">{t.method}</span></td>
                          <td>{(t.confidence * 100).toFixed(0)}%</td>
                          <td className="td-reason">{t.reason}</td>
                          <td>
                            <span className={`monitor-badge ${t.mitigated ? 'active' : 'offline'}`}>
                              {t.mitigated ? '✅ DONE' : '⏳ OPEN'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ════ INTEL TAB ════════════════════════════════════════════════ */}
        {tab === 'intel' && (
          <div className="tab-content">
            <div className="panel">
              <div className="panel-header">🔍 Indicators of Compromise (IOC) Database
                <button className="refresh-btn ml-auto" onClick={fetchIntel}>🔄</button>
              </div>
              <div className="table-wrapper">
                {iocs.length === 0 ? (
                  <div className="empty-state">No IOCs loaded</div>
                ) : (
                  <table className="data-table">
                    <thead>
                      <tr><th>ID</th><th>Type</th><th>Value</th><th>Source</th><th>Confidence</th><th>Added</th></tr>
                    </thead>
                    <tbody>
                      {iocs.map(ioc => (
                        <tr key={ioc.id}>
                          <td>#{ioc.id}</td>
                          <td><span className="method-badge">{ioc.type}</span></td>
                          <td className="td-mono">{ioc.value}</td>
                          <td>{ioc.source}</td>
                          <td>{(ioc.confidence * 100).toFixed(0)}%</td>
                          <td>{fmtDate(ioc.created_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ════ FORENSICS TAB ════════════════════════════════════════════ */}
        {tab === 'forensics' && (
          <div className="tab-content">
            <div className="chain-status-bar">
              <span>🔐 Chain Integrity:</span>
              {chainOk === null
                ? <span className="monitor-badge offline">Unknown</span>
                : chainOk
                  ? <span className="monitor-badge active">✅ Verified</span>
                  : <span className="monitor-badge" style={{ background:'rgba(248,81,73,.2)', color:'#f85149' }}>❌ Tampered</span>
              }
              <button className="refresh-btn" onClick={fetchForensics}>🔄 Refresh</button>
            </div>
            <div className="panel">
              <div className="panel-header">📋 Forensic Hash Chain</div>
              <div className="logs-body" style={{ maxHeight: 480 }}>
                {forensicEntries.length === 0
                  ? <div className="empty-state">No forensic entries yet</div>
                  : [...forensicEntries].reverse().map((e, i) => (
                    <div key={i} className={`log-entry ${e.severity || 'info'}`}>
                      <span className="log-time">#{e.seq}</span>
                      <SeverityBadge sev={e.severity || 'info'} />
                      <div>
                        <div className="log-message">{e.event_type}</div>
                        <div className="hash-display">{e.hash?.slice(0, 32)}…</div>
                      </div>
                    </div>
                  ))
                }
              </div>
            </div>
          </div>
        )}

        {/* ════ DEMO TAB ══════════════════════════════════════════════════ */}
        {tab === 'demo' && (
          <div className="tab-content demo-tab">
            <div className="demo-hero">
              <div className="demo-icon">🦠</div>
              <h2>Ransomware Attack Simulation</h2>
              <p>
                Safely demonstrates the full threat lifecycle — file creation,
                AI detection, autonomous response, and forensic logging —
                in a sandboxed environment. No real files are harmed.
              </p>
              <div className="demo-buttons">
                <button
                  className="demo-btn primary"
                  onClick={triggerDemo}
                  disabled={demoBusy}
                >
                  {demoBusy ? '⏳ Running simulation...' : '🚀 Launch Ransomware Demo'}
                </button>
                <button
                  className="demo-btn secondary"
                  onClick={triggerTest}
                  disabled={testBusy}
                >
                  {testBusy ? '⏳' : '🧪 Quick Threat Test'}
                </button>
              </div>
            </div>

            {demoResult && (
              <div className="panel demo-result">
                <div className="panel-header">
                  ✅ Simulation Result
                </div>
                <div className="demo-result-body">
                  <div className="result-row">
                    <span className="result-key">Status</span>
                    <span className="monitor-badge active">{String(demoResult.status)}</span>
                  </div>
                  <div className="result-row">
                    <span className="result-key">Files Created</span>
                    <span className="result-val">{String(demoResult.files_created ?? '—')}</span>
                  </div>
                  <div className="result-row">
                    <span className="result-key">Sandbox</span>
                    <span className="result-val td-mono">
                      {String((demoResult.simulation as any)?.sandbox ?? '—')}
                    </span>
                  </div>
                  <div className="result-row">
                    <span className="result-key">Events Triggered</span>
                    <span className="result-val">{String(demoResult.events_triggered ?? '—')}</span>
                  </div>
                  <div className="result-row">
                    <span className="result-key">Auto-Cleanup In</span>
                    <span className="result-val">{String(demoResult.cleanup_in_seconds ?? '—')}s</span>
                  </div>
                  <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 12 }}>
                    Watch the <strong>Dashboard → Event Stream</strong> to see threats being detected and quarantined in real time.
                  </p>
                </div>
              </div>
            )}

            {/* Architecture diagram */}
            <div className="panel">
              <div className="panel-header">🏗 System Architecture</div>
              <div className="arch-grid">
                {[
                  { icon: '📁', label: 'File Sensor',     sub: 'watchdog + entropy analysis' },
                  { icon: '🌐', label: 'Network Sensor',  sub: 'psutil + anomaly detection' },
                  { icon: '⚙️', label: 'Process Sensor',  sub: 'psutil deep scan' },
                  { icon: '🤖', label: 'RF Classifier',   sub: 'RandomForest ~100% acc' },
                  { icon: '🔍', label: 'IsoForest',       sub: 'Zero-day anomaly detection' },
                  { icon: '📏', label: 'Rule Engine',     sub: 'Hard threshold triggers' },
                  { icon: '💀', label: 'Kill Process',    sub: 'Auto-terminate threats' },
                  { icon: '🔒', label: 'Quarantine',      sub: 'File isolation sandbox' },
                  { icon: '🚫', label: 'Block IP',        sub: 'Firewall rule injection' },
                  { icon: '🗄', label: 'Threat DB',       sub: 'SQLite persistent store' },
                  { icon: '🔗', label: 'Forensic Chain',  sub: 'SHA-256 tamper-evident log' },
                  { icon: '🔄', label: 'Auto-Retrain',    sub: 'Continuous learning pipeline' },
                ].map(m => (
                  <div key={m.label} className="arch-card">
                    <div className="arch-icon">{m.icon}</div>
                    <div className="arch-label">{m.label}</div>
                    <div className="arch-sub">{m.sub}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
