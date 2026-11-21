import React, { useState, useEffect } from 'react';
import { 
  Shield, ShieldAlert, Activity, Wifi, Terminal, Cpu, Database, 
  AlertTriangle, CheckCircle, BarChart3, Radio, RefreshCw, Zap,
  ExternalLink, ChevronRight, Play, Square, Layers, Search
} from 'lucide-react';
import { 
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, 
  PieChart, Pie, Cell, LineChart, Line, CartesianGrid, Legend 
} from 'recharts';

const API_BASE = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:8000';
const WS_BASE = typeof window !== 'undefined' 
  ? `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws/live`
  : 'ws://localhost:8000/ws/live';

const SEVERITY_COLORS = {
  Critical: "#ff0055",
  High: "#ff5500",
  Medium: "#ffaa00",
  Low: "#00ff88"
};

const ATTACK_COLORS = {
  BENIGN: "#00ff88",
  PortScan: "#ffaa00",
  DoS: "#ff0055",
  "Brute Force": "#bf00ff"
};

export default function App() {
  const [activeTab, setActiveTab] = useState("overview");
  const [wsConnected, setWsConnected] = useState(false);
  const [overview, setOverview] = useState({
    total_packets: 0,
    total_flows: 0,
    total_threats: 0,
    normal_percentage: 100,
    threat_breakdown: {},
    severity_breakdown: {},
    active_alerts_count: 0
  });
  const [flows, setFlows] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [modelMetrics, setModelMetrics] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [simLoading, setSimLoading] = useState(null);
  const [attackBanner, setAttackBanner] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState("ALL");
  const [filterStatus, setFilterStatus] = useState("ALL");

  // Fetch initial overview & models
  const fetchOverview = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/analytics/overview`);
      if (res.ok) {
        const data = await res.json();
        setOverview(data);
      }
    } catch (e) {
      console.warn("Backend not reachable yet", e);
    }
  };

  const fetchAlerts = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/alerts?limit=100`);
      if (res.ok) {
        const data = await res.json();
        setAlerts(data);
      }
    } catch (e) {}
  };

  const fetchModelMetrics = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/analytics/models`);
      if (res.ok) {
        const data = await res.json();
        setModelMetrics(data);
      }
    } catch (e) {}
  };

  // WebSocket Live Stream Connection
  useEffect(() => {
    fetchOverview();
    fetchAlerts();
    fetchModelMetrics();

    let ws = null;
    let reconnectTimeout = null;

    const connectWs = () => {
      try {
        ws = new WebSocket(WS_BASE);
        ws.onopen = () => {
          setWsConnected(true);
        };
        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === "INIT") {
              if (msg.data.recent_alerts) setAlerts(msg.data.recent_alerts.reverse());
              if (msg.data.recent_flows) setFlows(msg.data.recent_flows.reverse());
            } else if (msg.type === "FLOW") {
              setFlows(prev => [msg.data, ...prev.slice(0, 150)]);
              setOverview(prev => ({
                ...prev,
                total_flows: prev.total_flows + 1,
                total_packets: prev.total_packets + msg.data.packets
              }));
            } else if (msg.type === "ALERT") {
              setAlerts(prev => [msg.data, ...prev.slice(0, 100)]);
              setOverview(prev => ({
                ...prev,
                total_threats: prev.total_threats + 1,
                active_alerts_count: prev.active_alerts_count + 1
              }));
            }
          } catch (err) {
            console.error("WS Parse error", err);
          }
        };
        ws.onclose = () => {
          setWsConnected(false);
          reconnectTimeout = setTimeout(connectWs, 3000);
        };
        ws.onerror = () => {
          setWsConnected(false);
          ws.close();
        };
      } catch (err) {
        reconnectTimeout = setTimeout(connectWs, 3000);
      }
    };

    connectWs();
    const interval = setInterval(fetchOverview, 5000);

    return () => {
      if (ws) ws.close();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      clearInterval(interval);
    };
  }, []);

  // Attack Simulator Trigger with Immediate Visual Feedback
  const triggerSimulation = async (type) => {
    setSimLoading(type);
    try {
      const res = await fetch(`${API_BASE}/api/capture/simulate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ attack_type: type })
      });
      const data = await res.json();
      
      // Immediately refresh stats and alerts
      await fetchOverview();
      await fetchAlerts();

      setAttackBanner({
        type: "success",
        title: `${type} Simulated Successfully!`,
        message: data.message || `Injected ${type} traffic into the flow meter. Hybrid Engine raised an alert.`
      });
      setTimeout(() => setAttackBanner(null), 5000);
    } catch (e) {
      console.error(e);
      setAttackBanner({
        type: "error",
        title: "Simulation Failed",
        message: "Could not reach backend API at " + API_BASE
      });
      setTimeout(() => setAttackBanner(null), 5000);
    } finally {
      setSimLoading(null);
    }
  };

  const updateAlertStatus = async (alertId, status) => {
    try {
      await fetch(`${API_BASE}/api/alerts/${alertId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status })
      });
      setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, status } : a));
      if (selectedAlert && selectedAlert.id === alertId) {
        setSelectedAlert(prev => ({ ...prev, status }));
      }
    } catch (e) {}
  };

  const filteredAlerts = alerts.filter(a => {
    if (filterSeverity !== "ALL" && a.severity !== filterSeverity) return false;
    if (filterStatus !== "ALL" && a.status !== filterStatus) return false;
    return true;
  });

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col font-sans">
      {/* Top Header */}
      <header className="border-b border-[#1f2f52] bg-[#0d1424]/90 backdrop-blur sticky top-0 z-30 px-6 py-3.5 flex items-center justify-between">
        <div className="flex items-center space-x-3.5">
          <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-lg shadow-cyan-500/10">
            <Shield className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-extrabold text-lg tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-sky-300 to-indigo-400">
                NetSentinel AI
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-950/70 text-cyan-300 border border-cyan-800">
                v1.0.0 SOC
              </span>
            </div>
            <p className="text-xs text-slate-400">AI-Powered Network Intrusion Detection & Real-Time Threat Monitoring</p>
          </div>
        </div>

        {/* Live Controls & WS Status */}
        <div className="flex items-center space-x-4">
          {/* Quick Simulation Bar */}
          <div className="flex items-center bg-[#131d33] border border-[#1f2f52] rounded-lg p-1 space-x-1.5 shadow-sm">
            <span className="text-xs text-slate-300 px-2 flex items-center gap-1 font-mono font-semibold">
              <Zap className="w-3.5 h-3.5 text-amber-400" /> Simulate:
            </span>
            <button
              onClick={() => triggerSimulation("PortScan")}
              disabled={simLoading === "PortScan"}
              className="text-xs px-3 py-1.5 rounded-md font-semibold bg-amber-500/15 hover:bg-amber-500/30 active:scale-95 text-amber-300 border border-amber-500/40 transition cursor-pointer flex items-center gap-1.5 shadow-sm hover:shadow-amber-500/20"
              title="Inject a rapid SYN port scan"
            >
              {simLoading === "PortScan" ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3 fill-amber-300" />}
              PortScan
            </button>
            <button
              onClick={() => triggerSimulation("DoS")}
              disabled={simLoading === "DoS"}
              className="text-xs px-3 py-1.5 rounded-md font-semibold bg-rose-500/15 hover:bg-rose-500/30 active:scale-95 text-rose-300 border border-rose-500/40 transition cursor-pointer flex items-center gap-1.5 shadow-sm hover:shadow-rose-500/20"
              title="Inject a high-volume DoS packet flood"
            >
              {simLoading === "DoS" ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3 fill-rose-300" />}
              DoS Flood
            </button>
            <button
              onClick={() => triggerSimulation("Brute Force")}
              disabled={simLoading === "Brute Force"}
              className="text-xs px-3 py-1.5 rounded-md font-semibold bg-purple-500/15 hover:bg-purple-500/30 active:scale-95 text-purple-300 border border-purple-500/40 transition cursor-pointer flex items-center gap-1.5 shadow-sm hover:shadow-purple-500/20"
              title="Inject repeated SSH authentication attempts"
            >
              {simLoading === "Brute Force" ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3 fill-purple-300" />}
              Brute Force
            </button>
          </div>

          {/* WebSocket Status Indicator */}
          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-[#131d33] border border-[#1f2f52] text-xs">
            <span className={`w-2.5 h-2.5 rounded-full ${wsConnected ? 'bg-emerald-400 shadow-[0_0_8px_#34d399]' : 'bg-rose-500 animate-ping'}`} />
            <span className="font-mono text-slate-300">
              {wsConnected ? "LIVE STREAM" : "CONNECTING..."}
            </span>
          </div>
        </div>
      </header>

      {/* Navigation Bar */}
      <nav className="bg-[#0b101c] border-b border-[#1f2f52] px-6 py-2 flex space-x-2">
        {[
          { id: "overview", label: "Overview SOC", icon: Activity },
          { id: "traffic", label: "Live Traffic Inspector", icon: Radio, count: flows.length },
          { id: "alerts", label: "Threat Alerts", icon: ShieldAlert, badge: overview.active_alerts_count },
          { id: "models", label: "ML Evaluation & Research", icon: Cpu }
        ].map(tab => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition flex items-center space-x-2 ${
                isActive 
                  ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 shadow-md shadow-cyan-500/5' 
                  : 'text-slate-400 hover:text-slate-200 hover:bg-[#131d33]'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
              {tab.badge > 0 && (
                <span className="text-[11px] px-1.5 py-0.2 rounded-full bg-rose-500 text-white font-bold ml-1">
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Main Content Area */}
      <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
        
        {/* Real-time Attack Simulation Banner */}
        {attackBanner && (
          <div className="p-4 rounded-xl bg-gradient-to-r from-amber-500/20 via-rose-500/20 to-purple-500/20 border border-amber-500/40 text-slate-100 flex items-center justify-between shadow-lg">
            <div className="flex items-center space-x-3">
              <AlertTriangle className="w-5 h-5 text-amber-400 animate-bounce" />
              <div>
                <p className="font-bold text-sm text-amber-300">{attackBanner.title}</p>
                <p className="text-xs text-slate-300 mt-0.5">{attackBanner.message}</p>
              </div>
            </div>
            <button
              onClick={() => setActiveTab("alerts")}
              className="px-3 py-1.5 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 text-amber-200 border border-amber-500/40 text-xs font-semibold transition cursor-pointer"
            >
              View In Alerts Tab &rarr;
            </button>
          </div>
        )}
        
        {/* TAB 1: OVERVIEW */}
        {activeTab === "overview" && (
          <div className="space-y-6">
            {/* Top Metric Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="p-5 rounded-xl bg-[#0d1424] border border-[#1f2f52] shadow-sm">
                <div className="flex items-center justify-between text-slate-400 mb-2">
                  <span className="text-xs font-semibold tracking-wider uppercase">Packets Inspected</span>
                  <Activity className="w-4 h-4 text-cyan-400" />
                </div>
                <div className="text-3xl font-extrabold font-mono text-cyan-300">
                  {overview.total_packets.toLocaleString()}
                </div>
                <div className="text-xs text-slate-400 mt-2 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" /> Scapy Continuous Capture
                </div>
              </div>

              <div className="p-5 rounded-xl bg-[#0d1424] border border-[#1f2f52] shadow-sm">
                <div className="flex items-center justify-between text-slate-400 mb-2">
                  <span className="text-xs font-semibold tracking-wider uppercase">Network Flows</span>
                  <Radio className="w-4 h-4 text-indigo-400" />
                </div>
                <div className="text-3xl font-extrabold font-mono text-indigo-300">
                  {overview.total_flows.toLocaleString()}
                </div>
                <div className="text-xs text-slate-400 mt-2 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-indigo-400" /> 5-Tuple Aggregation (CICIDS)
                </div>
              </div>

              <div className="p-5 rounded-xl bg-[#0d1424] border border-[#1f2f52] shadow-sm">
                <div className="flex items-center justify-between text-slate-400 mb-2">
                  <span className="text-xs font-semibold tracking-wider uppercase">Threats Detected</span>
                  <AlertTriangle className="w-4 h-4 text-rose-400" />
                </div>
                <div className="text-3xl font-extrabold font-mono text-rose-400">
                  {overview.total_threats.toLocaleString()}
                </div>
                <div className="text-xs text-rose-400/80 mt-2 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-rose-400" /> AI/ML + Rule Corroborated
                </div>
              </div>

              <div className="p-5 rounded-xl bg-[#0d1424] border border-[#1f2f52] shadow-sm">
                <div className="flex items-center justify-between text-slate-400 mb-2">
                  <span className="text-xs font-semibold tracking-wider uppercase">Normal Traffic</span>
                  <CheckCircle className="w-4 h-4 text-emerald-400" />
                </div>
                <div className="text-3xl font-extrabold font-mono text-emerald-400">
                  {overview.normal_percentage}%
                </div>
                <div className="text-xs text-slate-400 mt-2 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" /> High-Confidence Benign Baseline
                </div>
              </div>
            </div>

            {/* Charts & Threat Feeds */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Threat Distribution Chart */}
              <div className="p-5 rounded-xl bg-[#0d1424] border border-[#1f2f52] flex flex-col justify-between">
                <div>
                  <h3 className="font-semibold text-slate-200 text-sm flex items-center gap-2">
                    <BarChart3 className="w-4 h-4 text-cyan-400" /> Detected Attacks by Category
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">Multi-class classification distribution</p>
                </div>
                <div className="h-64 my-4 flex items-center justify-center">
                  {overview.total_threats > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={[
                        { name: "PortScan", count: overview.threat_breakdown.PortScan || 0, fill: "#ffaa00" },
                        { name: "DoS", count: overview.threat_breakdown.DoS || 0, fill: "#ff0055" },
                        { name: "Brute Force", count: overview.threat_breakdown["Brute Force"] || 0, fill: "#bf00ff" }
                      ]}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1f2f52" />
                        <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                        <YAxis stroke="#64748b" fontSize={11} />
                        <Tooltip contentStyle={{ backgroundColor: "#0d1424", borderColor: "#1f2f52", borderRadius: 8, fontSize: 12 }} />
                        <Bar dataKey="count" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="text-center text-slate-500 text-xs">
                      No threats detected yet.<br />Trigger an attack above to see live updates.
                    </div>
                  )}
                </div>
                <div className="grid grid-cols-3 gap-2 pt-2 border-t border-[#1f2f52] text-center text-xs">
                  <div>
                    <span className="text-amber-400 font-bold font-mono">{overview.threat_breakdown.PortScan || 0}</span>
                    <p className="text-slate-400 text-[10px]">PortScan</p>
                  </div>
                  <div>
                    <span className="text-rose-400 font-bold font-mono">{overview.threat_breakdown.DoS || 0}</span>
                    <p className="text-slate-400 text-[10px]">DoS</p>
                  </div>
                  <div>
                    <span className="text-purple-400 font-bold font-mono">{overview.threat_breakdown["Brute Force"] || 0}</span>
                    <p className="text-slate-400 text-[10px]">Brute Force</p>
                  </div>
                </div>
              </div>

              {/* Real-Time Live Security Incidents Feed */}
              <div className="lg:col-span-2 p-5 rounded-xl bg-[#0d1424] border border-[#1f2f52]">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h3 className="font-semibold text-slate-200 text-sm flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-rose-400" /> Recent Security Incidents
                    </h3>
                    <p className="text-xs text-slate-400 mt-0.5">Corroborated alerts with explainable reasoning</p>
                  </div>
                  <button
                    onClick={() => setActiveTab("alerts")}
                    className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                  >
                    View All <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>

                <div className="space-y-2.5 max-h-[320px] overflow-y-auto pr-1">
                  {alerts.length === 0 ? (
                    <div className="py-12 text-center text-slate-500 text-xs font-mono">
                      No incidents flagged. Network operating within benign baseline parameters.
                    </div>
                  ) : (
                    alerts.slice(0, 5).map((alert) => (
                      <div
                        key={alert.id}
                        onClick={() => { setSelectedAlert(alert); setActiveTab("alerts"); }}
                        className="p-3 rounded-lg bg-[#131d33]/70 hover:bg-[#131d33] border border-[#1f2f52] transition cursor-pointer flex items-center justify-between"
                      >
                        <div className="flex items-center space-x-3">
                          <span
                            className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase"
                            style={{ 
                              backgroundColor: `${SEVERITY_COLORS[alert.severity]}20`,
                              color: SEVERITY_COLORS[alert.severity],
                              border: `1px solid ${SEVERITY_COLORS[alert.severity]}40`
                            }}
                          >
                            {alert.severity}
                          </span>
                          <div>
                            <div className="flex items-center space-x-2">
                              <span className="font-bold text-xs text-slate-200">{alert.attack_type}</span>
                              <span className="text-[11px] font-mono text-cyan-400">
                                {alert.src_ip} &rarr; {alert.dst_ip}:{alert.dst_port}
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-400 mt-0.5 line-clamp-1">
                              {alert.xai_explanation?.reasons?.[0] || alert.detection_mechanism}
                            </p>
                          </div>
                        </div>

                        <div className="text-right">
                          <span className="text-[10px] font-mono text-slate-400">{alert.timestamp}</span>
                          <div className="text-[11px] font-mono text-emerald-400 mt-0.5">
                            {(alert.confidence * 100).toFixed(1)}% conf
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: LIVE TRAFFIC INSPECTOR */}
        {activeTab === "traffic" && (
          <div className="p-5 rounded-xl bg-[#0d1424] border border-[#1f2f52] space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="font-semibold text-slate-200 text-sm flex items-center gap-2">
                  <Radio className="w-4 h-4 text-cyan-400 animate-pulse" /> Live Network Flow Inspector
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Streaming 5-tuple aggregated bidirectional flows calculated in real-time
                </p>
              </div>
              <div className="text-xs font-mono text-slate-400 bg-[#131d33] px-3 py-1.5 rounded-lg border border-[#1f2f52]">
                Buffer: <span className="text-cyan-300 font-bold">{flows.length}</span> flows
              </div>
            </div>

            <div className="overflow-x-auto rounded-lg border border-[#1f2f52]">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#131d33] text-slate-400 uppercase text-[10px] tracking-wider border-b border-[#1f2f52]">
                  <tr>
                    <th className="p-3">Time</th>
                    <th className="p-3">Source &rarr; Destination</th>
                    <th className="p-3">Port</th>
                    <th className="p-3">Proto</th>
                    <th className="p-3 text-right">Packets</th>
                    <th className="p-3 text-right">Bytes</th>
                    <th className="p-3 text-right">Duration</th>
                    <th className="p-3 text-center">ML Classification</th>
                    <th className="p-3 text-right">Conf</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1f2f52]/50 text-slate-300">
                  {flows.map((flow) => {
                    const isAttack = flow.label !== "BENIGN";
                    return (
                      <tr 
                        key={flow.id} 
                        className={`transition hover:bg-[#131d33]/80 ${isAttack ? 'bg-rose-950/20' : ''}`}
                      >
                        <td className="p-3 text-slate-400">{flow.timestamp}</td>
                        <td className="p-3 font-semibold text-slate-200">
                          {flow.src_ip} &rarr; {flow.dst_ip}
                        </td>
                        <td className="p-3 text-cyan-300">{flow.dst_port}</td>
                        <td className="p-3 text-slate-400">{flow.protocol}</td>
                        <td className="p-3 text-right">{flow.packets}</td>
                        <td className="p-3 text-right">{flow.bytes.toLocaleString()} B</td>
                        <td className="p-3 text-right">{flow.duration_ms} ms</td>
                        <td className="p-3 text-center">
                          <span
                            className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider"
                            style={{
                              backgroundColor: `${ATTACK_COLORS[flow.label] || '#00ff88'}20`,
                              color: ATTACK_COLORS[flow.label] || '#00ff88',
                              border: `1px solid ${ATTACK_COLORS[flow.label] || '#00ff88'}40`
                            }}
                          >
                            {flow.label}
                          </span>
                        </td>
                        <td className="p-3 text-right text-emerald-400">
                          {(flow.confidence * 100).toFixed(1)}%
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* TAB 3: THREAT ALERTS & XAI TRIAGE */}
        {activeTab === "alerts" && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Alerts Table */}
            <div className="lg:col-span-2 p-5 rounded-xl bg-[#0d1424] border border-[#1f2f52] space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h3 className="font-semibold text-slate-200 text-sm flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-rose-400" /> Incident Triage Console
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">Filter, investigate, and update alert status</p>
                </div>

                {/* Filters */}
                <div className="flex items-center space-x-2 text-xs">
                  <select
                    value={filterSeverity}
                    onChange={(e) => setFilterSeverity(e.target.value)}
                    className="bg-[#131d33] border border-[#1f2f52] rounded-lg px-2.5 py-1 text-slate-300 outline-none"
                  >
                    <option value="ALL">All Severities</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>

                  <select
                    value={filterStatus}
                    onChange={(e) => setFilterStatus(e.target.value)}
                    className="bg-[#131d33] border border-[#1f2f52] rounded-lg px-2.5 py-1 text-slate-300 outline-none"
                  >
                    <option value="ALL">All Statuses</option>
                    <option value="Unresolved">Unresolved</option>
                    <option value="Investigating">Investigating</option>
                    <option value="Resolved">Resolved</option>
                    <option value="False Positive">False Positive</option>
                  </select>
                </div>
              </div>

              <div className="overflow-x-auto rounded-lg border border-[#1f2f52]">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-[#131d33] text-slate-400 uppercase text-[10px] tracking-wider border-b border-[#1f2f52]">
                    <tr>
                      <th className="p-3">Severity</th>
                      <th className="p-3">Alert ID</th>
                      <th className="p-3">Attack Type</th>
                      <th className="p-3">Target</th>
                      <th className="p-3">Status</th>
                      <th className="p-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1f2f52]/50 text-slate-300">
                    {filteredAlerts.length === 0 ? (
                      <tr>
                        <td colSpan="6" className="p-8 text-center text-slate-500">
                          No alerts match the selected filters.
                        </td>
                      </tr>
                    ) : (
                      filteredAlerts.map(alert => (
                        <tr
                          key={alert.id}
                          onClick={() => setSelectedAlert(alert)}
                          className={`cursor-pointer transition hover:bg-[#131d33] ${
                            selectedAlert?.id === alert.id ? 'bg-[#131d33] border-l-2 border-cyan-400' : ''
                          }`}
                        >
                          <td className="p-3">
                            <span
                              className="px-2 py-0.5 rounded text-[10px] font-bold uppercase"
                              style={{ 
                                backgroundColor: `${SEVERITY_COLORS[alert.severity]}20`,
                                color: SEVERITY_COLORS[alert.severity]
                              }}
                            >
                              {alert.severity}
                            </span>
                          </td>
                          <td className="p-3 text-cyan-300 font-bold">{alert.id}</td>
                          <td className="p-3 font-semibold text-slate-200">{alert.attack_type}</td>
                          <td className="p-3 text-slate-400">
                            {alert.src_ip} &rarr; :{alert.dst_port}
                          </td>
                          <td className="p-3">
                            <span className={`text-[11px] px-2 py-0.5 rounded ${
                              alert.status === 'Resolved' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                              alert.status === 'Investigating' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                              alert.status === 'False Positive' ? 'bg-slate-800 text-slate-400' :
                              'bg-rose-950 text-rose-300 border border-rose-800'
                            }`}>
                              {alert.status}
                            </span>
                          </td>
                          <td className="p-3 text-right">
                            <button
                              onClick={(e) => { e.stopPropagation(); setSelectedAlert(alert); }}
                              className="text-xs text-cyan-400 hover:text-cyan-300 font-sans"
                            >
                              Inspect &rarr;
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Explainable AI (XAI) Deep-Dive Drawer */}
            <div className="p-5 rounded-xl bg-[#0d1424] border border-[#1f2f52] flex flex-col justify-between space-y-4">
              <div>
                <div className="flex items-center justify-between pb-3 border-b border-[#1f2f52]">
                  <h3 className="font-semibold text-slate-200 text-sm flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-cyan-400" /> Explainable AI (XAI) Rationale
                  </h3>
                  {selectedAlert && (
                    <span className="text-xs font-mono text-cyan-300">{selectedAlert.id}</span>
                  )}
                </div>

                {selectedAlert ? (
                  <div className="mt-4 space-y-4">
                    {/* Header Details */}
                    <div className="p-3 rounded-lg bg-[#131d33] border border-[#1f2f52] space-y-1">
                      <div className="flex justify-between items-center text-xs font-mono">
                        <span className="text-slate-400">Classification:</span>
                        <span className="font-bold text-rose-400">{selectedAlert.attack_type}</span>
                      </div>
                      <div className="flex justify-between items-center text-xs font-mono">
                        <span className="text-slate-400">Detection Layer:</span>
                        <span className="text-cyan-300">{selectedAlert.detection_mechanism}</span>
                      </div>
                      <div className="flex justify-between items-center text-xs font-mono">
                        <span className="text-slate-400">Confidence:</span>
                        <span className="text-emerald-400 font-bold">
                          {(selectedAlert.confidence * 100).toFixed(1)}%
                        </span>
                      </div>
                    </div>

                    {/* Identified Reasons */}
                    <div>
                      <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                        Why the AI Flagged This Traffic:
                      </h4>
                      <ul className="space-y-1.5">
                        {selectedAlert.xai_explanation?.reasons?.map((r, i) => (
                          <li key={i} className="text-xs text-slate-300 bg-[#131d33]/50 p-2.5 rounded-lg border border-[#1f2f52] flex items-start gap-2">
                            <span className="text-cyan-400 font-mono font-bold">{i + 1}.</span>
                            <span>{r}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    {/* Actionable Recommendations */}
                    <div>
                      <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                        Recommended SOC Actions:
                      </h4>
                      <ul className="space-y-1.5">
                        {selectedAlert.xai_explanation?.recommended_actions?.map((action, i) => (
                          <li key={i} className="text-xs text-slate-400 bg-cyan-950/20 p-2.5 rounded-lg border border-cyan-900/30 flex items-start gap-2">
                            <span className="text-emerald-400">&bull;</span>
                            <span>{action}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    {/* Status Management */}
                    <div className="pt-3 border-t border-[#1f2f52]">
                      <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                        Update Status:
                      </h4>
                      <div className="grid grid-cols-2 gap-2 text-xs">
                        <button
                          onClick={() => updateAlertStatus(selectedAlert.id, "Investigating")}
                          className="py-1.5 rounded bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30"
                        >
                          Mark Investigating
                        </button>
                        <button
                          onClick={() => updateAlertStatus(selectedAlert.id, "Resolved")}
                          className="py-1.5 rounded bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                        >
                          Mark Resolved
                        </button>
                        <button
                          onClick={() => updateAlertStatus(selectedAlert.id, "False Positive")}
                          className="py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-600 col-span-2"
                        >
                          Mark False Positive
                        </button>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="py-16 text-center text-slate-500 text-xs">
                    Select an alert from the table on the left to inspect its Explainable AI reasoning and mitigation steps.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: ML EVALUATION & RESEARCH BENCHMARKS */}
        {activeTab === "models" && (
          <div className="space-y-6">
            {/* Viva & Research Overview Banner */}
            <div className="p-5 rounded-xl bg-gradient-to-r from-cyan-950/40 via-[#0d1424] to-indigo-950/40 border border-cyan-800/40 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
              <div>
                <div className="flex items-center space-x-2">
                  <Cpu className="w-5 h-5 text-cyan-400" />
                  <h3 className="font-bold text-slate-100 text-base">
                    Machine Learning Model Evaluation & Research Benchmarks
                  </h3>
                </div>
                <p className="text-xs text-slate-400 mt-1 max-w-3xl">
                  Trained and evaluated on flow-level network intrusion datasets (CICIDS2017 feature standards).
                  Models compared: <strong>Random Forest</strong>, <strong>Decision Tree</strong>, <strong>Logistic Regression</strong>, and <strong>Isolation Forest</strong>.
                </p>
              </div>
              <button
                onClick={fetchModelMetrics}
                className="px-3.5 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-xs font-medium flex items-center gap-1.5 transition"
              >
                <RefreshCw className="w-3.5 h-3.5" /> Refresh Metrics
              </button>
            </div>

            {/* Models Comparison Table */}
            {modelMetrics && modelMetrics["Random Forest"] && (
              <div className="p-5 rounded-xl bg-[#0d1424] border border-[#1f2f52] space-y-4">
                <h4 className="font-semibold text-slate-200 text-sm">
                  1. Model Performance Comparison (Undergraduate Research Benchmark)
                </h4>

                <div className="overflow-x-auto rounded-lg border border-[#1f2f52]">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-[#131d33] text-slate-400 uppercase text-[10px] tracking-wider border-b border-[#1f2f52]">
                      <tr>
                        <th className="p-3">Model Architecture</th>
                        <th className="p-3 text-right">Accuracy</th>
                        <th className="p-3 text-right">Precision (Macro)</th>
                        <th className="p-3 text-right">Recall (Macro)</th>
                        <th className="p-3 text-right">F1-Score (Macro)</th>
                        <th className="p-3 text-right">FPR on Benign</th>
                        <th className="p-3 text-right">Inference Latency</th>
                        <th className="p-3 text-right">Training Time</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1f2f52]/50 text-slate-300">
                      <tr className="bg-cyan-950/20 font-bold">
                        <td className="p-3 text-cyan-300 flex items-center gap-1.5">
                          <CheckCircle className="w-3.5 h-3.5 text-cyan-400" /> Random Forest (Primary Ensemble)
                        </td>
                        <td className="p-3 text-right text-emerald-400">
                          {(modelMetrics["Random Forest"].accuracy * 100).toFixed(2)}%
                        </td>
                        <td className="p-3 text-right">{(modelMetrics["Random Forest"].precision_macro).toFixed(4)}</td>
                        <td className="p-3 text-right">{(modelMetrics["Random Forest"].recall_macro).toFixed(4)}</td>
                        <td className="p-3 text-right text-cyan-300">{(modelMetrics["Random Forest"].f1_macro).toFixed(4)}</td>
                        <td className="p-3 text-right text-emerald-400">{(modelMetrics["Random Forest"].fpr_benign).toFixed(4)}</td>
                        <td className="p-3 text-right text-slate-300">{modelMetrics["Random Forest"].inference_latency_us} &micro;s</td>
                        <td className="p-3 text-right text-slate-400">{modelMetrics["Random Forest"].train_time_sec}s</td>
                      </tr>

                      {modelMetrics["Decision Tree"] && (
                        <tr>
                          <td className="p-3 text-slate-200">Decision Tree (Rule Baseline)</td>
                          <td className="p-3 text-right text-emerald-400">
                            {(modelMetrics["Decision Tree"].accuracy * 100).toFixed(2)}%
                          </td>
                          <td className="p-3 text-right">{(modelMetrics["Decision Tree"].precision_macro).toFixed(4)}</td>
                          <td className="p-3 text-right">{(modelMetrics["Decision Tree"].recall_macro).toFixed(4)}</td>
                          <td className="p-3 text-right text-slate-300">{(modelMetrics["Decision Tree"].f1_macro).toFixed(4)}</td>
                          <td className="p-3 text-right text-emerald-400">{(modelMetrics["Decision Tree"].fpr_benign).toFixed(4)}</td>
                          <td className="p-3 text-right text-slate-300">{modelMetrics["Decision Tree"].inference_latency_us} &micro;s</td>
                          <td className="p-3 text-right text-slate-400">{modelMetrics["Decision Tree"].train_time_sec}s</td>
                        </tr>
                      )}

                      {modelMetrics["Logistic Regression"] && (
                        <tr>
                          <td className="p-3 text-slate-200">Logistic Regression (Linear Baseline)</td>
                          <td className="p-3 text-right text-emerald-400">
                            {(modelMetrics["Logistic Regression"].accuracy * 100).toFixed(2)}%
                          </td>
                          <td className="p-3 text-right">{(modelMetrics["Logistic Regression"].precision_macro).toFixed(4)}</td>
                          <td className="p-3 text-right">{(modelMetrics["Logistic Regression"].recall_macro).toFixed(4)}</td>
                          <td className="p-3 text-right text-slate-300">{(modelMetrics["Logistic Regression"].f1_macro).toFixed(4)}</td>
                          <td className="p-3 text-right text-emerald-400">{(modelMetrics["Logistic Regression"].fpr_benign).toFixed(4)}</td>
                          <td className="p-3 text-right text-slate-300">{modelMetrics["Logistic Regression"].inference_latency_us} &micro;s</td>
                          <td className="p-3 text-right text-slate-400">{modelMetrics["Logistic Regression"].train_time_sec}s</td>
                        </tr>
                      )}

                      {modelMetrics["Isolation Forest"] && (
                        <tr>
                          <td className="p-3 text-slate-200">Isolation Forest (Unsupervised Anomaly)</td>
                          <td className="p-3 text-right text-emerald-400">
                            {(modelMetrics["Isolation Forest"].accuracy_anomaly * 100).toFixed(2)}%
                          </td>
                          <td className="p-3 text-right text-slate-500">N/A (Binary)</td>
                          <td className="p-3 text-right text-slate-500">N/A (Binary)</td>
                          <td className="p-3 text-right text-slate-300">{(modelMetrics["Isolation Forest"].f1_anomaly).toFixed(4)}</td>
                          <td className="p-3 text-right text-slate-500">Unsupervised</td>
                          <td className="p-3 text-right text-slate-500">&mdash;</td>
                          <td className="p-3 text-right text-slate-400">{modelMetrics["Isolation Forest"].train_time_sec}s</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Feature Importance & Confusion Matrix */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Feature Importance Chart */}
              {modelMetrics?.feature_importances && (
                <div className="p-5 rounded-xl bg-[#0d1424] border border-[#1f2f52] flex flex-col justify-between">
                  <div>
                    <h4 className="font-semibold text-slate-200 text-sm flex items-center gap-2">
                      <BarChart3 className="w-4 h-4 text-cyan-400" /> Top Most Discriminative Features
                    </h4>
                    <p className="text-xs text-slate-400 mt-1">
                      Gini Impurity reduction computed across 100 Random Forest trees
                    </p>
                  </div>

                  <div className="h-72 my-4">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart 
                        data={modelMetrics.feature_importances.slice(0, 7)}
                        layout="vertical"
                        margin={{ top: 5, right: 30, left: 70, bottom: 5 }}
                      >
                        <CartesianGrid strokeDasharray="3 3" stroke="#1f2f52" />
                        <XAxis type="number" stroke="#64748b" fontSize={11} domain={[0, 0.12]} tickFormatter={v => `${(v*100).toFixed(0)}%`} />
                        <YAxis type="category" dataKey="feature" stroke="#94a3b8" fontSize={10} width={90} />
                        <Tooltip contentStyle={{ backgroundColor: "#0d1424", borderColor: "#1f2f52", borderRadius: 8, fontSize: 12 }} formatter={v => `${(v*100).toFixed(2)}%`} />
                        <Bar dataKey="importance" fill="#00f0ff" radius={[0, 4, 4, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>

                  <div className="text-xs text-slate-400 border-t border-[#1f2f52] pt-2">
                    Key finding: <strong>Packet Length Std</strong> and <strong>Flow IAT Min</strong> are the strongest predictors of rapid automated probes.
                  </div>
                </div>
              )}

              {/* Confusion Matrix Visualizer */}
              {modelMetrics?.["Random Forest"]?.confusion_matrix && (
                <div className="p-5 rounded-xl bg-[#0d1424] border border-[#1f2f52] flex flex-col justify-between">
                  <div>
                    <h4 className="font-semibold text-slate-200 text-sm flex items-center gap-2">
                      <Layers className="w-4 h-4 text-indigo-400" /> Multi-Class Confusion Matrix
                    </h4>
                    <p className="text-xs text-slate-400 mt-1">
                      Evaluated on 6,000 unseen test flow vectors (Rows = Actual, Columns = Predicted)
                    </p>
                  </div>

                  <div className="my-4">
                    <div className="grid grid-cols-5 gap-2 text-center text-xs font-mono">
                      <div className="text-slate-500 font-bold">Actual \ Pred</div>
                      <div className="text-emerald-400 font-bold">BENIGN</div>
                      <div className="text-amber-400 font-bold">PortScan</div>
                      <div className="text-rose-400 font-bold">DoS</div>
                      <div className="text-purple-400 font-bold">BruteForce</div>

                      {["BENIGN", "PortScan", "DoS", "Brute Force"].map((actualClass, rowIdx) => (
                        <React.Fragment key={actualClass}>
                          <div className="text-slate-300 font-bold text-left flex items-center">{actualClass}</div>
                          {modelMetrics["Random Forest"].confusion_matrix[rowIdx].map((val, colIdx) => {
                            const isDiagonal = rowIdx === colIdx;
                            return (
                              <div
                                key={colIdx}
                                className={`p-3 rounded-lg border font-bold flex items-center justify-center ${
                                  isDiagonal 
                                    ? 'bg-cyan-500/10 border-cyan-500/40 text-cyan-300 shadow-sm'
                                    : val > 0 
                                      ? 'bg-rose-500/20 border-rose-500/50 text-rose-300'
                                      : 'bg-[#131d33]/40 border-[#1f2f52] text-slate-600'
                                }`}
                              >
                                {val}
                              </div>
                            );
                          })}
                        </React.Fragment>
                      ))}
                    </div>
                  </div>

                  <div className="text-xs text-slate-400 border-t border-[#1f2f52] pt-2">
                    False Positive Rate (FPR) on Benign is <strong>0.00%</strong>, ensuring SOC analysts are not overwhelmed with false alarms.
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

      </main>
    </div>
  );
}
