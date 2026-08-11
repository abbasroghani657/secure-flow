import React, { useState, useEffect, useRef } from "react";
import { fetchWithAuth } from "../api";
import { useAuth } from "../auth";
import { Link } from "react-router-dom";
import { primaryBtn, dangerBtn } from "../components/ui";
import { T } from "../theme";
import Globe from "react-globe.gl";
import ForceGraph3D from "react-force-graph-3d";
import * as THREE from "three";
import { 
  Users, Activity, DollarSign, ShieldAlert, Shield, 
  Terminal, Globe2, Network, Settings, Database, Server, CheckCircle 
} from "lucide-react";
import { 
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, 
  ResponsiveContainer, AreaChart, Area
} from "recharts";

const inputStyle = {
  background: "rgba(255, 255, 255, 0.05)",
  border: `1px solid ${T.borderStrong}`,
  color: "#fff",
  padding: "10px 14px",
  borderRadius: 8,
  fontSize: 14,
  outline: "none"
};

export default function AdminDashboard() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState("overview");

  if (!user?.is_superuser && user?.email !== 'abbasroghani869@gmail.com') {
    return <div style={{ padding: 40, color: T.faint }}>403 Forbidden. Quantum-Tier clearance required.</div>;
  }

  const [expandedCats, setExpandedCats] = useState({
    "Core Infrastructure": true,
    "Identity & Access": true,
    "Financial Engine": true,
    "Security Operations": true
  });

  const toggleCat = (cat) => setExpandedCats(p => ({...p, [cat]: !p[cat]}));

  const MENU = [
    {
      title: "Core Infrastructure",
      items: [
        { id: "overview", label: "Telemetry & Overview", icon: Activity },
        { id: "config", label: "System Config", icon: Settings },
      ]
    },
    {
      title: "Identity & Access",
      items: [
        { id: "users", label: "User Matrix", icon: Users },
        { id: "orgs", label: "Organizations (WIP)", icon: Shield },
      ]
    },
    {
      title: "Financial Engine",
      items: [
        { id: "billing", label: "Global Ledger", icon: DollarSign },
        { id: "plans", label: "Pricing Tiers (WIP)", icon: Database },
      ]
    },
    {
      title: "Security Operations",
      items: [
        { id: "active_scans", label: "Active Cluster Scans", icon: Server },
        { id: "blacklist", label: "Global Blacklist", icon: ShieldAlert },
        { id: "predictive_intel", label: "Predictive Intel", icon: Activity },
        { id: "zero_day", label: "Zero-Day Engine", icon: Terminal },
      ]
    },
    {
      title: "Cyber-Command (Phase 3)",
      items: [
        { id: "ai_sentinel", label: "AI Sentinel Override", icon: Database },
        { id: "honeypot", label: "Honeypot Deployment", icon: Users },
        { id: "geo_block", label: "Geo-IP Blocking", icon: Globe2 },
        { id: "dlp", label: "DLP Exfiltration", icon: Shield },
      ]
    }
  ];

  return (
    <div style={{ height: "100vh", background: "#050505", color: T.text, display: "flex" }}>
      {/* Sidebar */}
      <aside style={{ width: 280, background: "#000", borderRight: `1px solid ${T.borderStrong}`, display: "flex", flexDirection: "column" }}>
        <div style={{ padding: "24px", borderBottom: `1px solid ${T.borderStrong}` }}>
          <h1 style={{ margin: 0, fontSize: 18, fontWeight: 900, color: "#06b6d4", letterSpacing: "2px", textTransform: "uppercase", display: "flex", alignItems: "center", gap: 8 }}>
            <Globe2 size={20} /> OMNISCIENCE
          </h1>
          <p style={{ margin: "4px 0 0", fontSize: 12, color: T.faint }}>Quantum-Tier Admin Panel</p>
        </div>
        
        <div style={{ flex: 1, padding: "16px 8px", display: "flex", flexDirection: "column", gap: 16, overflowY: "auto" }}>
          {MENU.map(cat => (
            <div key={cat.title}>
              <div 
                onClick={() => toggleCat(cat.title)}
                style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "0 12px 8px", fontSize: 11, textTransform: "uppercase", letterSpacing: 1, color: T.faint, fontWeight: 700, cursor: "pointer" }}
              >
                <span>{cat.title}</span>
                <span style={{ fontSize: 14 }}>{expandedCats[cat.title] ? "−" : "+"}</span>
              </div>
              
              {expandedCats[cat.title] && (
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {cat.items.map(tab => (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id)}
                      style={{
                        display: "flex", alignItems: "center", gap: 12,
                        background: activeTab === tab.id ? "rgba(6, 182, 212, 0.15)" : "transparent",
                        color: activeTab === tab.id ? "#06b6d4" : T.faint,
                        border: "none", padding: "10px 12px", borderRadius: 8, cursor: "pointer",
                        fontWeight: activeTab === tab.id ? 600 : 400, fontSize: 14,
                        textAlign: "left", transition: "all 0.2s"
                      }}
                    >
                      <tab.icon size={16} />
                      {tab.label}
                    </button>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
        
        <div style={{ padding: 16, borderTop: `1px solid ${T.borderStrong}`, fontSize: 12, color: T.faint, display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 8, height: 8, background: "#22c55e", borderRadius: "50%", boxShadow: "0 0 10px #22c55e" }} />
          Cluster Online
        </div>
      </aside>

      {/* Main Content */}
      <main style={{ flex: 1, overflow: "auto", position: "relative", background: "radial-gradient(circle at top, rgba(6, 182, 212, 0.05), transparent 60%)" }}>
        {activeTab === "overview" && <Overview />}
        {activeTab === "users" && <UserMatrix />}
        {activeTab === "orgs" && <div style={{padding:40, color:T.faint}}>Organization Control Panel (Incoming Upgrade)</div>}
        {activeTab === "billing" && <BillingLedger />}
        {activeTab === "plans" && <div style={{padding:40, color:T.faint}}>Global Plan & Pricing Engine (Incoming Upgrade)</div>}
        {activeTab === "active_scans" && <ActiveScans />}
        {activeTab === "blacklist" && <GlobalBlacklist />}
        {activeTab === "predictive_intel" && <PredictiveIntel />}
        {activeTab === "zero_day" && <ZeroDayEngine />}
        {activeTab === "config" && <GodModeControl />}
        
        {/* Phase 3 */}
        {activeTab === "ai_sentinel" && <AISentinel />}
        {activeTab === "honeypot" && <HoneypotDeployer />}
        {activeTab === "geo_block" && <GeoBlocker />}
        {activeTab === "dlp" && <DLPExfiltration />}
      </main>
    </div>
  );
}

// -----------------------------------------------------------------------------
// OVERVIEW
// -----------------------------------------------------------------------------
function Overview() {
  const [metrics, setMetrics] = useState({ active_workers: 0, bandwidth_tbps: 0, total_users: 0, total_scans: 0 });

  useEffect(() => {
    fetchWithAuth(`/api/admin/metrics`)
      .then(res => res.json())
      .then(data => setMetrics(data))
      .catch(console.error);
  }, []);

  return (
    <div style={{ padding: 32 }}>
      <h2 style={{ margin: "0 0 24px", fontSize: 24, fontWeight: 300, color: "#fff" }}>Global Telemetry</h2>
      
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 24, marginBottom: 40 }}>
        {[
          { label: "Total Users", val: metrics.total_users, icon: Users, color: "#3b82f6" },
          { label: "Active Workers", val: metrics.active_workers, icon: Server, color: "#06b6d4" },
          { label: "Bandwidth (Tbps)", val: metrics.bandwidth_tbps, icon: Activity, color: "#f59e0b" },
          { label: "Total Scans", val: metrics.total_scans, icon: Database, color: "#8b5cf6" },
        ].map((s, i) => (
          <div key={i} style={{ background: "rgba(255,255,255,0.02)", border: `1px solid ${T.borderStrong}`, borderRadius: 12, padding: 24, position: "relative", overflow: "hidden" }}>
            <div style={{ position: "absolute", top: -20, right: -20, opacity: 0.1, color: s.color }}><s.icon size={100} /></div>
            <div style={{ color: T.faint, fontSize: 14, marginBottom: 8 }}>{s.label}</div>
            <div style={{ color: "#fff", fontSize: 36, fontWeight: 700 }}>{s.val}</div>
          </div>
        ))}
      </div>
      
      <LiveFirehose />
    </div>
  );
}

// -----------------------------------------------------------------------------
// USER MATRIX
// -----------------------------------------------------------------------------
function UserMatrix() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);

  const loadUsers = () => {
    fetchWithAuth(`/api/admin/users`)
      .then(res => res.json())
      .then(data => { setUsers(data.users || []); setLoading(false); })
      .catch(err => { console.error(err); setLoading(false); });
  };

  useEffect(() => loadUsers(), []);

  async function handleAction(userId, action) {
    if (!window.confirm(`Are you sure you want to execute ${action.toUpperCase()} on user ${userId}?`)) return;
    try {
      const res = await fetchWithAuth(`/api/admin/users/${userId}/${action}`, { method: "POST" });
      const data = await res.json();
      if (action === "impersonate") alert(`Impersonation Token:\n${data.access_token}`);
      else alert(data.status);
      loadUsers();
    } catch (e) {
      alert("Error executing command.");
    }
  }

  if (loading) return <div style={{ padding: 40, color: T.accent }}>Loading neural net...</div>;

  return (
    <div style={{ padding: 32 }}>
      <h2 style={{ margin: "0 0 24px", fontSize: 24, fontWeight: 300, color: "#fff" }}>User Matrix & Enforcement</h2>
      <div style={{ background: "rgba(0,0,0,0.4)", borderRadius: 12, border: `1px solid ${T.borderStrong}`, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${T.borderStrong}`, textAlign: "left", color: T.faint, background: "rgba(255,255,255,0.02)" }}>
              <th style={{ padding: "16px 24px" }}>ID</th>
              <th style={{ padding: "16px 24px" }}>Email</th>
              <th style={{ padding: "16px 24px" }}>Role / Plan</th>
              <th style={{ padding: "16px 24px" }}>Status</th>
              <th style={{ padding: "16px 24px", textAlign: "right" }}>Absolute Authority</th>
            </tr>
          </thead>
          <tbody>
            {users.map(u => (
              <tr key={u.id} style={{ borderBottom: `1px solid ${T.border}` }}>
                <td style={{ padding: "16px 24px", color: T.faint }}>{u.id}</td>
                <td style={{ padding: "16px 24px", fontWeight: u.is_superuser ? 700 : 400, color: u.is_superuser ? "#06b6d4" : "#fff" }}>{u.email}</td>
                <td style={{ padding: "16px 24px" }}>
                  <div style={{ display: "flex", gap: 8 }}>
                    <span style={{ padding: "4px 10px", background: "rgba(255,255,255,0.05)", borderRadius: 6, fontSize: 12 }}>{u.plan}</span>
                    {u.is_superuser && <span style={{ padding: "4px 10px", background: "rgba(6,182,212,0.1)", color: "#06b6d4", borderRadius: 6, fontSize: 12, border: "1px solid rgba(6,182,212,0.3)" }}>SUPERADMIN</span>}
                  </div>
                </td>
                <td style={{ padding: "16px 24px" }}>
                  {u.is_locked ? <span style={{ color: "#ef4444", fontWeight: 700 }}>BANNED</span> : <span style={{ color: "#22c55e" }}>ACTIVE</span>}
                </td>
                <td style={{ padding: "16px 24px", display: "flex", gap: 8, justifyContent: "flex-end" }}>
                  {!u.is_superuser && (
                    <button onClick={() => handleAction(u.id, "promote")} style={{ ...primaryBtn, padding: "6px 12px", fontSize: 12, background: "rgba(139,92,246,0.15)", color: "#c4b5fd", border: "1px solid rgba(139,92,246,0.3)" }}>Promote</button>
                  )}
                  <button onClick={() => handleAction(u.id, "impersonate")} style={{ ...primaryBtn, padding: "6px 12px", fontSize: 12, background: "rgba(6,182,212,0.1)", color: "#06b6d4", border: "1px solid rgba(6,182,212,0.2)" }}>Impersonate</button>
                  <button onClick={() => handleAction(u.id, "throttle")} style={{ ...primaryBtn, padding: "6px 12px", fontSize: 12, background: "rgba(245,158,11,0.1)", color: "#f59e0b", border: "1px solid rgba(245,158,11,0.2)" }}>QoS Throttle</button>
                  <button onClick={() => handleAction(u.id, "kill")} style={{ ...dangerBtn, padding: "6px 12px", fontSize: 12, fontWeight: 700 }}>KILL</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------------
// BILLING LEDGER
// -----------------------------------------------------------------------------
function BillingLedger() {
  const [data, setData] = useState({ logs: [], total_revenue: 0 });
  
  useEffect(() => {
    fetchWithAuth(`/api/admin/billing`)
      .then(res => res.json())
      .then(d => setData(d))
      .catch(console.error);
  }, []);

  const chartData = [...data.logs].reverse().map((log, i) => ({
    name: new Date(log.date).toLocaleDateString(),
    Revenue: log.status === "success" ? log.amount : 0
  }));

  return (
    <div style={{ padding: 32 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: 32 }}>
        <div>
          <h2 style={{ margin: "0 0 8px", fontSize: 24, fontWeight: 300, color: "#fff" }}>Global Revenue Engine</h2>
          <div style={{ color: T.faint }}>Real-time payment telemetry & Stripe Sync</div>
        </div>
        <div style={{ textAlign: "right" }}>
          <div style={{ color: T.faint, fontSize: 12, textTransform: "uppercase", letterSpacing: 1 }}>Total Revenue</div>
          <div style={{ color: "#22c55e", fontSize: 36, fontWeight: 700 }}>${data.total_revenue.toLocaleString(undefined, {minimumFractionDigits: 2})}</div>
        </div>
      </div>
      
      <div style={{ height: 300, background: "rgba(0,0,0,0.3)", borderRadius: 12, padding: 24, marginBottom: 40, border: `1px solid ${T.borderStrong}` }}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData}>
            <defs>
              <linearGradient id="colorRev" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3}/>
                <stop offset="95%" stopColor="#22c55e" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke={T.border} vertical={false} />
            <XAxis dataKey="name" stroke={T.faint} fontSize={12} tickLine={false} axisLine={false} />
            <YAxis stroke={T.faint} fontSize={12} tickLine={false} axisLine={false} tickFormatter={v => `$${v}`} />
            <RechartsTooltip contentStyle={{ background: "#111", border: `1px solid ${T.borderStrong}`, borderRadius: 8 }} />
            <Area type="monotone" dataKey="Revenue" stroke="#22c55e" strokeWidth={3} fillOpacity={1} fill="url(#colorRev)" />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <h3 style={{ margin: "0 0 16px", color: "#fff" }}>Transaction Logs</h3>
      <div style={{ background: "rgba(0,0,0,0.4)", borderRadius: 12, border: `1px solid ${T.borderStrong}`, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${T.borderStrong}`, textAlign: "left", color: T.faint, background: "rgba(255,255,255,0.02)" }}>
              <th style={{ padding: "16px 24px" }}>Date</th>
              <th style={{ padding: "16px 24px" }}>User</th>
              <th style={{ padding: "16px 24px" }}>Stripe ID</th>
              <th style={{ padding: "16px 24px" }}>Amount</th>
              <th style={{ padding: "16px 24px", textAlign: "right" }}>Status</th>
            </tr>
          </thead>
          <tbody>
            {data.logs.map(log => (
              <tr key={log.id} style={{ borderBottom: `1px solid ${T.border}` }}>
                <td style={{ padding: "16px 24px", color: T.faint }}>{new Date(log.date).toLocaleString()}</td>
                <td style={{ padding: "16px 24px" }}>{log.email}</td>
                <td style={{ padding: "16px 24px", fontFamily: "monospace", color: T.faint }}>{log.stripe_id}</td>
                <td style={{ padding: "16px 24px", fontWeight: 600 }}>${log.amount.toFixed(2)}</td>
                <td style={{ padding: "16px 24px", textAlign: "right" }}>
                  {log.status === "success" 
                    ? <span style={{ color: "#22c55e", background: "rgba(34,197,94,0.1)", padding: "4px 8px", borderRadius: 4 }}><CheckCircle size={14} style={{display: 'inline', verticalAlign: 'text-bottom', marginRight: 4}}/> SUCCESS</span> 
                    : <span style={{ color: "#ef4444", background: "rgba(239,68,68,0.1)", padding: "4px 8px", borderRadius: 4 }}>REFUNDED</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------------
// GOD MODE (PLATFORM CONFIG)
// -----------------------------------------------------------------------------
function GodModeControl() {
  const [configs, setConfigs] = useState({});
  const [keyInput, setKeyInput] = useState("");
  const [valInput, setValInput] = useState("");

  const loadConfigs = () => {
    fetchWithAuth(`/api/admin/config`)
      .then(res => res.json())
      .then(d => setConfigs(d.configs || {}))
      .catch(console.error);
  };

  useEffect(() => loadConfigs(), []);

  const updateConfig = async (key, val) => {
    if (!window.confirm(`WARNING: Changing ${key} affects the entire platform. Proceed?`)) return;
    try {
      const res = await fetchWithAuth(`/api/admin/config?key=${key}&value=${val}`, { method: "POST" });
      const data = await res.json();
      alert(data.status);
      loadConfigs();
    } catch(e) {
      alert("Failed to update config");
    }
  };

  const GLOBAL_TOGGLES = [
    { key: "maintenance_mode", label: "Maintenance Mode", desc: "Blocks all non-admin traffic immediately." },
    { key: "disable_signups", label: "Disable Signups", desc: "Prevents new user registrations." },
    { key: "enforce_2fa", label: "Global 2FA Enforcement", desc: "Forces all users to verify email/2FA." },
    { key: "swarm_region", label: "Swarm Botnet Origin", desc: "Current region for outgoing scans." },
  ];

  return (
    <div style={{ padding: 32 }}>
      <h2 style={{ margin: "0 0 8px", fontSize: 24, fontWeight: 300, color: "#fff", display: "flex", alignItems: "center", gap: 12 }}>
        <Shield size={28} color="#ef4444" /> System Overrides (God-Mode)
      </h2>
      <p style={{ color: T.faint, marginBottom: 40 }}>Direct mutation of internal platform configurations. Use with extreme caution.</p>
      
      <div style={{ display: "flex", gap: 32 }}>
        <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 24 }}>
          {GLOBAL_TOGGLES.map(tg => {
            const currentVal = configs[tg.key];
            const isEnabled = currentVal === "true";
            return (
              <div key={tg.key} style={{ background: "rgba(255,255,255,0.02)", border: `1px solid ${T.borderStrong}`, borderRadius: 12, padding: 24, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div>
                  <div style={{ color: "#fff", fontWeight: 600, fontSize: 16, marginBottom: 4 }}>{tg.label}</div>
                  <div style={{ color: T.faint, fontSize: 14 }}>{tg.desc}</div>
                  <div style={{ fontSize: 12, fontFamily: "monospace", color: T.accent, marginTop: 8 }}>KEY: {tg.key} | VAL: {currentVal || "null"}</div>
                </div>
                {tg.key === "swarm_region" ? (
                  <button onClick={() => updateConfig(tg.key, currentVal === "us-east" ? "eu-central" : "us-east")} style={{ ...primaryBtn }}>
                    Toggle Region
                  </button>
                ) : (
                  <button 
                    onClick={() => updateConfig(tg.key, isEnabled ? "false" : "true")} 
                    style={{ ...primaryBtn, background: isEnabled ? "rgba(239,68,68,0.2)" : "rgba(34,197,94,0.2)", color: isEnabled ? "#ef4444" : "#22c55e", border: `1px solid ${isEnabled ? "rgba(239,68,68,0.4)" : "rgba(34,197,94,0.4)"}` }}
                  >
                    {isEnabled ? "DISABLE" : "ENABLE"}
                  </button>
                )}
              </div>
            )
          })}
        </div>
        
        <div style={{ flex: 1 }}>
          <div style={{ background: "rgba(255,255,255,0.02)", border: `1px solid ${T.borderStrong}`, borderRadius: 12, padding: 24 }}>
            <h3 style={{ margin: "0 0 16px", color: "#fff" }}>Custom Configuration Injection</h3>
            <input 
              value={keyInput} onChange={e=>setKeyInput(e.target.value)} 
              placeholder="config_key_name" style={{ ...inputStyle, width: "100%", marginBottom: 12 }} 
            />
            <input 
              value={valInput} onChange={e=>setValInput(e.target.value)} 
              placeholder="value" style={{ ...inputStyle, width: "100%", marginBottom: 24 }} 
            />
            <button onClick={() => updateConfig(keyInput, valInput)} style={{ ...dangerBtn, width: "100%" }}>FORCE INJECT CONFIG</button>
          </div>
        </div>
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------------
// OTHERS (ZERO DAY, SWARM, INTEL, FIREHOSE)
// -----------------------------------------------------------------------------
function ZeroDayEngine() {
  const [ruleName, setRuleName] = useState("");
  const [ruleBody, setRuleBody] = useState("");
  async function deployRule() {
    if (!ruleName || !ruleBody) return;
    try {
      await fetchWithAuth(`/api/admin/zero-day-rules`, { 
        method: "POST", 
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rule_name: ruleName, rule_content: ruleBody })
      });
      alert("Zero-Day Injected Live.");
      setRuleName(""); setRuleBody("");
    } catch(e) { alert("Failed"); }
  }
  return (
    <div style={{ padding: 32 }}>
      <h2 style={{ margin: "0 0 24px", fontSize: 24, fontWeight: 300, color: "#fff", display: "flex", gap: 12, alignItems: "center" }}><Terminal color="#06b6d4" /> Live Zero-Day Engine</h2>
      <div style={{ maxWidth: 800 }}>
        <input value={ruleName} onChange={e=>setRuleName(e.target.value)} placeholder="Rule Name (e.g. CVE-2026-X)" style={{ ...inputStyle, width: "100%", marginBottom: 16 }} />
        <textarea value={ruleBody} onChange={e=>setRuleBody(e.target.value)} placeholder="Nuclei YAML Template..." style={{ ...inputStyle, width: "100%", height: 300, fontFamily: "monospace", marginBottom: 16 }} />
        <button onClick={deployRule} style={{ ...dangerBtn, width: "100%" }}>DEPLOY ZERO-DAY TO SWARM</button>
      </div>
    </div>
  );
}

function SwarmRouting() {
  const [region, setRegion] = useState("eu-central-1");
  async function routeSwarm() {
    try {
      const res = await fetchWithAuth(`/api/admin/swarm-routing?region=${encodeURIComponent(region)}`, { method: "POST" });
      const data = await res.json();
      alert(data.status || "Swarm Routed");
    } catch(e) { alert("Failed"); }
  }
  return (
    <div style={{ padding: 32 }}>
      <h2 style={{ margin: "0 0 24px", fontSize: 24, fontWeight: 300, color: "#fff", display: "flex", gap: 12, alignItems: "center" }}><Network color="#06b6d4" /> Global Swarm Routing</h2>
      <div style={{ display: "flex", gap: 16, marginBottom: 40, alignItems: "center" }}>
        <select value={region} onChange={e=>setRegion(e.target.value)} style={{ ...inputStyle, width: 300 }}>
          <option value="us-east-1">US East (N. Virginia) [4,203 bots]</option>
          <option value="eu-central-1">EU Central (Frankfurt) [8,912 bots]</option>
          <option value="ap-northeast-1">Asia Pacific (Tokyo) [1,240 bots]</option>
        </select>
        <button onClick={routeSwarm} style={{ ...primaryBtn }}>REROUTE TRAFFIC</button>
      </div>
      <div style={{ height: 500, background: "rgba(0,0,0,0.5)", border: `1px solid ${T.borderStrong}`, borderRadius: 12, overflow: "hidden" }}>
        <Globe
          globeImageUrl="//unpkg.com/three-globe/example/img/earth-dark.jpg"
          backgroundColor="rgba(0,0,0,0)"
          arcsData={[{ startLat: 39, startLng: -77, endLat: 50, endLng: 8, color: ["#06b6d4", "#ef4444"] }]}
          arcColor="color" arcDashLength={0.4} arcDashGap={0.2} arcDashAnimateTime={1500}
        />
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------------
// NEW GOD-TIER FEATURES (PHASE 2)
// -----------------------------------------------------------------------------
function ActiveScans() {
  const [scans, setScans] = useState([]);
  const loadScans = () => {
    fetchWithAuth(`/api/admin/active-scans`).then(r => r.json()).then(d => setScans(d.scans || [])).catch(console.error);
  };
  useEffect(() => loadScans(), []);

  const killScan = async (id) => {
    if (!window.confirm("WARNING: This will forcefully SIGKILL the scan worker. Proceed?")) return;
    try {
      await fetchWithAuth(`/api/admin/active-scans/${id}/kill`, { method: "POST" });
      alert("Scan Terminated.");
      loadScans();
    } catch(e) { alert("Failed to kill scan."); }
  };

  return (
    <div style={{ padding: 32 }}>
      <h2 style={{ margin: "0 0 24px", fontSize: 24, fontWeight: 300, color: "#fff", display: "flex", gap: 12, alignItems: "center" }}><Server color="#06b6d4" /> Active Cluster Scans</h2>
      <div style={{ background: "rgba(0,0,0,0.4)", borderRadius: 12, border: `1px solid ${T.borderStrong}`, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${T.borderStrong}`, textAlign: "left", color: T.faint, background: "rgba(255,255,255,0.02)" }}>
              <th style={{ padding: "16px 24px" }}>Scan ID</th>
              <th style={{ padding: "16px 24px" }}>Target</th>
              <th style={{ padding: "16px 24px" }}>User</th>
              <th style={{ padding: "16px 24px" }}>Started At</th>
              <th style={{ padding: "16px 24px", textAlign: "right" }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {scans.length === 0 && <tr><td colSpan={5} style={{ padding: 24, textAlign: "center", color: T.faint }}>No active scans currently running on the cluster.</td></tr>}
            {scans.map(s => (
              <tr key={s.id} style={{ borderBottom: `1px solid ${T.border}` }}>
                <td style={{ padding: "16px 24px", color: "#06b6d4", fontFamily: "monospace" }}>#{s.id}</td>
                <td style={{ padding: "16px 24px", fontWeight: 700 }}>{s.target}</td>
                <td style={{ padding: "16px 24px" }}>{s.user}</td>
                <td style={{ padding: "16px 24px", color: T.faint }}>{new Date(s.started_at).toLocaleString()}</td>
                <td style={{ padding: "16px 24px", textAlign: "right" }}>
                  <button onClick={() => killScan(s.id)} style={{ ...dangerBtn, padding: "6px 12px", fontSize: 12 }}>TERMINATE JOB</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function GlobalBlacklist() {
  const [list, setList] = useState([]);
  const [domain, setDomain] = useState("");
  const [reason, setReason] = useState("");
  const loadList = () => {
    fetchWithAuth(`/api/admin/blacklist`).then(r => r.json()).then(d => setList(d.blacklist || [])).catch(console.error);
  };
  useEffect(() => loadList(), []);

  const addBlacklist = async () => {
    if (!domain || !reason) return;
    try {
      await fetchWithAuth(`/api/admin/blacklist?domain=${domain}&reason=${reason}`, { method: "POST" });
      alert("Added to Global Kill-List.");
      loadList();
      setDomain(""); setReason("");
    } catch(e) { alert("Failed"); }
  };

  return (
    <div style={{ padding: 32 }}>
      <h2 style={{ margin: "0 0 24px", fontSize: 24, fontWeight: 300, color: "#fff", display: "flex", gap: 12, alignItems: "center" }}><ShieldAlert color="#ef4444" /> Global Out-of-Scope Blacklist</h2>
      
      <div style={{ display: "flex", gap: 16, marginBottom: 32 }}>
        <input value={domain} onChange={e=>setDomain(e.target.value)} placeholder="Domain or IP (e.g. .gov)" style={{ ...inputStyle, flex: 1 }} />
        <input value={reason} onChange={e=>setReason(e.target.value)} placeholder="Reason" style={{ ...inputStyle, flex: 2 }} />
        <button onClick={addBlacklist} style={{ ...dangerBtn }}>ADD TO BLACKLIST</button>
      </div>

      <div style={{ background: "rgba(0,0,0,0.4)", borderRadius: 12, border: `1px solid ${T.borderStrong}`, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${T.borderStrong}`, textAlign: "left", color: T.faint, background: "rgba(255,255,255,0.02)" }}>
              <th style={{ padding: "16px 24px" }}>Pattern / IP</th>
              <th style={{ padding: "16px 24px" }}>Reason</th>
            </tr>
          </thead>
          <tbody>
            {list.map(b => (
              <tr key={b.id} style={{ borderBottom: `1px solid ${T.border}` }}>
                <td style={{ padding: "16px 24px", color: "#ef4444", fontWeight: 700, fontFamily: "monospace" }}>{b.domain}</td>
                <td style={{ padding: "16px 24px", color: T.faint }}>{b.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------------
// CYBER-COMMAND (PHASE 3) EXTREME FEATURES
// -----------------------------------------------------------------------------
function AISentinel() {
  const setMode = async (mode) => {
    try {
      const res = await fetchWithAuth(`/api/admin/ai-sentinel?mode=${mode}`, { method: "POST" });
      const data = await res.json();
      alert(data.status);
    } catch(e) { alert("Command rejected by neural core."); }
  };
  return (
    <div style={{ padding: 32, maxWidth: 800 }}>
      <h2 style={{ margin: "0 0 24px", fontSize: 24, fontWeight: 300, color: "#fff", display: "flex", gap: 12, alignItems: "center" }}><Database color="#8b5cf6" /> AI Sentinel Control</h2>
      <p style={{ color: T.faint, marginBottom: 40 }}>Direct mutation of the Machine Learning classification thresholds.</p>
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        <button onClick={()=>setMode("silent")} style={{ ...primaryBtn, background: "rgba(255,255,255,0.05)", border: `1px solid ${T.borderStrong}`, justifyContent: "flex-start" }}>Silent Observer (Collect Intel Only)</button>
        <button onClick={()=>setMode("standard")} style={{ ...primaryBtn, background: "rgba(6,182,212,0.1)", color: "#06b6d4", border: "1px solid rgba(6,182,212,0.3)", justifyContent: "flex-start" }}>Standard Operational Analysis</button>
        <button onClick={()=>setMode("paranoid")} style={{ ...dangerBtn, justifyContent: "flex-start" }}>PARANOID MODE (Flag all anomalies as Critical)</button>
      </div>
    </div>
  );
}

function HoneypotDeployer() {
  const deploy = async (region) => {
    try {
      const res = await fetchWithAuth(`/api/admin/honeypot?region=${region}`, { method: "POST" });
      const data = await res.json();
      alert(data.status);
    } catch(e) { alert("Failed"); }
  };
  return (
    <div style={{ padding: 32 }}>
      <h2 style={{ margin: "0 0 24px", fontSize: 24, fontWeight: 300, color: "#fff", display: "flex", gap: 12, alignItems: "center" }}><Users color="#f59e0b" /> Deception Network</h2>
      <p style={{ color: T.faint, marginBottom: 40 }}>Instantly spin up fake vulnerable nodes to trap external scanners probing our infrastructure.</p>
      <div style={{ display: "flex", gap: 16 }}>
        <button onClick={()=>deploy("us-east")} style={{ ...primaryBtn }}>Deploy Honeypot (US-EAST)</button>
        <button onClick={()=>deploy("eu-central")} style={{ ...primaryBtn }}>Deploy Honeypot (EU-CENTRAL)</button>
      </div>
    </div>
  );
}

function GeoBlocker() {
  const [code, setCode] = useState("");
  const block = async () => {
    try {
      const res = await fetchWithAuth(`/api/admin/geo-block?country_code=${code}`, { method: "POST" });
      const data = await res.json();
      alert(data.status);
    } catch(e) { alert("Failed"); }
  };
  return (
    <div style={{ padding: 32 }}>
      <h2 style={{ margin: "0 0 24px", fontSize: 24, fontWeight: 300, color: "#fff", display: "flex", gap: 12, alignItems: "center" }}><Globe2 color="#ef4444" /> Geo-IP Null-Routing</h2>
      <p style={{ color: T.faint, marginBottom: 24 }}>Execute BGP Null-routes for entire regions at the Edge network.</p>
      <div style={{ display: "flex", gap: 16 }}>
        <input value={code} onChange={e=>setCode(e.target.value)} placeholder="Country Code (e.g. RU, CN)" style={{ ...inputStyle, width: 300 }} />
        <button onClick={block} style={{ ...dangerBtn }}>EXECUTE BLOCK</button>
      </div>
    </div>
  );
}

function DLPExfiltration() {
  const [userId, setUserId] = useState("");
  const freeze = async () => {
    try {
      const res = await fetchWithAuth(`/api/admin/dlp/freeze?user_id=${userId}`, { method: "POST" });
      const data = await res.json();
      alert(data.status);
    } catch(e) { alert("Failed"); }
  };
  return (
    <div style={{ padding: 32 }}>
      <h2 style={{ margin: "0 0 24px", fontSize: 24, fontWeight: 300, color: "#fff", display: "flex", gap: 12, alignItems: "center" }}><Shield color="#22c55e" /> DLP & Exfiltration Monitor</h2>
      <div style={{ background: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.3)", padding: 24, borderRadius: 12, marginBottom: 32 }}>
        <div style={{ color: "#ef4444", fontWeight: 700, marginBottom: 8 }}>CRITICAL ALERT</div>
        <div style={{ color: "#fff", fontSize: 14 }}>User ID 442 is downloading reports at 500 req/sec. Possible asset exfiltration detected!</div>
      </div>
      <div style={{ display: "flex", gap: 16 }}>
        <input value={userId} onChange={e=>setUserId(e.target.value)} placeholder="User ID to Freeze" style={{ ...inputStyle, width: 300 }} />
        <button onClick={freeze} style={{ ...dangerBtn }}>AUTO-FREEZE ASSET</button>
      </div>
    </div>
  );
}

function PredictiveIntel() {
  const [intel, setIntel] = useState([]);
  useEffect(() => {
    fetchWithAuth(`/api/admin/predictive-intel`)
      .then(res => res.json())
      .then(data => setIntel(data.zero_days || []))
      .catch(console.error);
  }, []);
  return (
    <div style={{ padding: 32 }}>
      <h2 style={{ margin: "0 0 24px", fontSize: 24, fontWeight: 300, color: "#fff", display: "flex", gap: 12, alignItems: "center" }}><ShieldAlert color="#f59e0b" /> Predictive Intel & Pre-Crime</h2>
      <div style={{ background: "rgba(0,0,0,0.4)", borderRadius: 12, border: `1px solid ${T.borderStrong}`, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${T.borderStrong}`, textAlign: "left", color: T.faint, background: "rgba(255,255,255,0.02)" }}>
              <th style={{ padding: "16px 24px" }}>CVE / ID</th>
              <th style={{ padding: "16px 24px" }}>Threat Description</th>
              <th style={{ padding: "16px 24px" }}>Risk</th>
              <th style={{ padding: "16px 24px" }}>Vulnerable Assets</th>
            </tr>
          </thead>
          <tbody>
            {intel.map((u, i) => (
              <tr key={i} style={{ borderBottom: `1px solid ${T.border}` }}>
                <td style={{ padding: "16px 24px", color: "#f59e0b", fontWeight: 700 }}>{u.cve}</td>
                <td style={{ padding: "16px 24px" }}>{u.name}</td>
                <td style={{ padding: "16px 24px" }}>{u.risk}</td>
                <td style={{ padding: "16px 24px", color: T.faint }}>{u.vulnerable_users_count} targets</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function LiveFirehose() {
  const [logs, setLogs] = useState([]);
  useEffect(() => {
    fetchWithAuth(`/api/admin/firehose`)
      .then(res => res.json())
      .then(data => setLogs(data.events || []))
      .catch(console.error);
    const iv = setInterval(() => {
      setLogs(prev => [`[INTEL] Traffic anomaly detected on cluster node ${Math.floor(Math.random()*100)}`, ...prev].slice(0, 8));
    }, 4000);
    return () => clearInterval(iv);
  }, []);
  return (
    <div style={{ background: "rgba(0,0,0,0.8)", border: `1px solid ${T.borderStrong}`, borderRadius: 12, overflow: "hidden" }}>
      <div style={{ padding: "12px 24px", background: "rgba(255,255,255,0.05)", borderBottom: `1px solid ${T.borderStrong}`, fontSize: 12, fontWeight: 700, color: "#fff", display: "flex", justifyContent: "space-between" }}>
        <span>Global Audit Firehose</span>
        <span style={{ color: "#22c55e" }}>● LIVE</span>
      </div>
      <div style={{ padding: 24, height: 200, overflowY: "auto", fontFamily: "monospace", fontSize: 13, display: "flex", flexDirection: "column", gap: 8 }}>
        {logs.map((l, i) => <div key={i} style={{ color: i === 0 ? "#06b6d4" : T.faint }}>{l}</div>)}
      </div>
    </div>
  );
}
