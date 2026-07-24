import { useEffect, useState, useMemo } from "react";
import { useParams, Link } from "react-router-dom";
import { AppNav } from "../components/ui";
import { api } from "../api";
import { T, SEVERITY, scoreColor } from "../theme";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

// Confidence chip styling — how sure the scanner is about a finding.
const CONF = {
  confirmed: { label: "Confirmed", color: "#34d399", border: "rgba(52,211,153,0.35)", bg: "rgba(52,211,153,0.10)", hint: "Proven with an exploit marker, timing, error, or exact match" },
  firm: { label: "Firm", color: "#60a5fa", border: "rgba(96,165,250,0.35)", bg: "rgba(96,165,250,0.10)", hint: "A directly observed configuration fact" },
  tentative: { label: "Tentative", color: "#fbbf24", border: "rgba(251,191,36,0.35)", bg: "rgba(251,191,36,0.10)", hint: "A heuristic that may need manual review" },
};

const OWASP_NAMES = {
  "A01:2025": "Broken Access Control",
  "A02:2025": "Security Misconfiguration",
  "A03:2025": "Software Supply Chain Failures",
  "A04:2025": "Cryptographic Failures",
  "A05:2025": "Injection",
  "A06:2025": "Insecure Design",
  "A07:2025": "Identification & Authentication Failures",
  "A08:2025": "Software & Data Integrity Failures",
  "A09:2025": "Logging & Alerting Failures",
  "A10:2025": "Mishandling of Exceptional Conditions",
};

export default function ScanResults() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [err, setErr] = useState("");
  const [tab, setTab] = useState("findings"); // findings | passed | compliance
  const [sevFilter, setSevFilter] = useState("all");
  const [open, setOpen] = useState({});

  useEffect(() => {
    let alive = true;
    let timer;
    async function poll() {
      try {
        const data = await api.getScan(id);
        if (!alive) return;
        setScan(data);
        if (data.status === "running" || data.status === "queued") {
          timer = setTimeout(poll, 1500);
        }
      } catch (e) {
        if (alive) setErr(e.message);
      }
    }
    poll();
    return () => { alive = false; clearTimeout(timer); };
  }, [id]);

  const findings = scan?.findings || [];
  const issues = useMemo(() => findings.filter((f) => !f.passed), [findings]);
  const passed = useMemo(() => findings.filter((f) => f.passed), [findings]);

  const visibleIssues = useMemo(
    () => (sevFilter === "all" ? issues : issues.filter((f) => f.severity === sevFilter)),
    [issues, sevFilter]
  );

  // Group issues by OWASP Top 10:2025 category for the compliance view.
  const compliance = useMemo(() => {
    const map = {};
    for (const f of issues) {
      const cat = f.owasp || "Unmapped";
      (map[cat] = map[cat] || []).push(f);
    }
    return Object.entries(map).sort((a, b) => {
      if (a[0] === "Unmapped") return 1;
      if (b[0] === "Unmapped") return -1;
      return a[0].localeCompare(b[0]);
    });
  }, [issues]);

  if (err) return <Shell><p style={{ color: "#F87171" }}>{err}</p></Shell>;
  if (!scan) return <Shell><p style={{ color: T.muted }}>Loading…</p></Shell>;

  const running = scan.status === "running" || scan.status === "queued";
  const counts = { critical: scan.critical_count, high: scan.high_count, medium: scan.medium_count, low: scan.low_count, info: scan.info_count };

  return (
    <Shell>
      <Link to="/dashboard" style={{ fontSize: 13, color: T.muted, display: "inline-flex", alignItems: "center", gap: 6, marginBottom: 18 }}>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M15 18l-6-6 6-6" /></svg>
        All scans
      </Link>

      <div style={{ display: "flex", gap: 20, alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", marginBottom: 8 }}>
        <h1 style={{ fontFamily: T.mono, fontSize: 22, fontWeight: 500, margin: 0, wordBreak: "break-all" }}>{scan.target_url}</h1>
        {scan.status === "completed" && (
          <Link to={`/scans/${scan.id}/report`} style={{ display: "inline-flex", alignItems: "center", gap: 8, background: "none", border: `1px solid ${T.borderStrong}`, color: T.text, fontSize: 13.5, fontWeight: 600, padding: "9px 16px", borderRadius: 10, whiteSpace: "nowrap" }}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" /><path d="M14 2v6h6M12 18v-6M9 15h6" /></svg>
            Export report
          </Link>
        )}
      </div>
      <p style={{ color: T.muted, fontSize: 13.5, margin: "0 0 28px", display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
        <span>{scan.scan_type} scan · {new Date(scan.created_at).toLocaleString()}</span>
        {scan.trigger === "scheduled" && (
          <span style={{ fontSize: 11, fontWeight: 600, color: T.accentHi, border: "1px solid rgba(0,191,99,0.35)", background: "rgba(0,191,99,0.08)", borderRadius: 999, padding: "2px 9px" }}>Scheduled</span>
        )}
        {scan.status === "completed" && scan.new_findings_count > 0 && (
          <span style={{ fontSize: 11, fontWeight: 700, color: T.accentInk, background: T.accent, borderRadius: 999, padding: "2px 9px" }}>{scan.new_findings_count} new since last scan</span>
        )}
        {scan.status === "failed" && <span style={{ color: "#F87171" }}> · {scan.error}</span>}
      </p>

      {running ? (
        <RunningState scan={scan} />
      ) : scan.status === "failed" ? (
        <div style={{ padding: "32px", borderRadius: 16, border: "1px solid rgba(248,113,113,0.3)", background: "rgba(220,38,38,0.08)" }}>
          <h2 style={{ margin: "0 0 8px", fontFamily: T.heading, color: "#F87171" }}>Scan failed</h2>
          <p style={{ color: T.muted, margin: 0 }}>{scan.error || "The target could not be scanned."}</p>
        </div>
      ) : (
        <>
          {/* Summary */}
          <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: 28, alignItems: "center", padding: "26px 28px", borderRadius: 18, border: `1px solid ${T.border}`, background: T.panel, marginBottom: 28, flexWrap: "wrap" }}>
            <ScoreRing score={scan.security_score} />
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(90px, 1fr))", gap: 14 }}>
              {SEV_ORDER.map((s) => (
                <div key={s} style={{ textAlign: "center", padding: "12px 8px", borderRadius: 12, border: `1px solid ${SEVERITY[s].border}`, background: SEVERITY[s].bg }}>
                  <div style={{ fontFamily: T.heading, fontSize: 26, fontWeight: 700, color: SEVERITY[s].color }}>{counts[s]}</div>
                  <div style={{ fontSize: 11.5, color: T.muted, textTransform: "uppercase", letterSpacing: "0.06em", marginTop: 2 }}>{SEVERITY[s].label}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Tabs */}
          <div style={{ display: "flex", gap: 6, borderBottom: `1px solid ${T.border}`, marginBottom: 20 }}>
            {[["findings", `Findings (${issues.length})`], ["passed", `Passed (${passed.length})`], ["compliance", "OWASP Top 10"]].map(([k, label]) => (
              <button key={k} onClick={() => setTab(k)} style={{ background: "none", border: "none", borderBottom: `2px solid ${tab === k ? T.accent : "transparent"}`, color: tab === k ? T.text : T.muted, cursor: "pointer", padding: "10px 14px", fontFamily: T.body, fontSize: 14, fontWeight: 600, marginBottom: -1 }}>
                {label}
              </button>
            ))}
          </div>

          {tab === "findings" && (
            <>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 18 }}>
                <FilterChip active={sevFilter === "all"} onClick={() => setSevFilter("all")} label={`All (${issues.length})`} color={T.text} />
                {SEV_ORDER.filter((s) => counts[s] > 0).map((s) => (
                  <FilterChip key={s} active={sevFilter === s} onClick={() => setSevFilter(s)} label={`${SEVERITY[s].label} (${counts[s]})`} color={SEVERITY[s].color} />
                ))}
              </div>
              {visibleIssues.length === 0 ? (
                <Empty text="No findings in this category. Nice." />
              ) : (
                <div style={{ display: "grid", gap: 12 }}>
                  {visibleIssues.map((f) => (
                    <FindingCard key={f.id} f={f} open={!!open[f.id]} onToggle={() => setOpen((o) => ({ ...o, [f.id]: !o[f.id] }))} />
                  ))}
                </div>
              )}
            </>
          )}

          {tab === "passed" && (
            passed.length === 0 ? <Empty text="No passed checks recorded." /> : (
              <div style={{ display: "grid", gap: 10 }}>
                {passed.map((f) => (
                  <div key={f.id} style={{ display: "flex", gap: 12, alignItems: "center", padding: "14px 16px", borderRadius: 12, border: `1px solid ${T.border}`, background: "rgba(0,191,99,0.04)" }}>
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={T.accent} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 6L9 17l-5-5" /></svg>
                    <div>
                      <div style={{ fontSize: 14.5, fontWeight: 600 }}>{f.title}</div>
                      <div style={{ fontSize: 12.5, color: T.muted }}>{f.description}</div>
                    </div>
                    <span style={{ marginLeft: "auto", fontSize: 11.5, color: T.faint }}>{f.compliance_ref}</span>
                  </div>
                ))}
              </div>
            )
          )}

          {tab === "compliance" && (
            compliance.length === 0 ? <Empty text="No compliance gaps found." /> : (
              <div style={{ display: "grid", gap: 14 }}>
                {compliance.map(([ref, items]) => (
                  <div key={ref} style={{ padding: "18px 20px", borderRadius: 14, border: `1px solid ${T.border}` }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 10, gap: 12 }}>
                      <span style={{ fontFamily: T.heading, fontWeight: 600, fontSize: 15 }}>
                        {ref === "Unmapped" ? "Unmapped" : <><span style={{ color: T.accentHi }}>{ref}</span> — {OWASP_NAMES[ref] || ""}</>}
                      </span>
                      <span style={{ fontSize: 12.5, color: T.muted, whiteSpace: "nowrap" }}>{items.length} issue{items.length !== 1 ? "s" : ""}</span>
                    </div>
                    <div style={{ display: "grid", gap: 6 }}>
                      {items.map((f) => (
                        <div key={f.id} style={{ display: "flex", gap: 10, alignItems: "center", fontSize: 13.5 }}>
                          <span style={{ width: 8, height: 8, borderRadius: "50%", background: SEVERITY[f.severity].color }} />
                          <span style={{ color: T.muted }}>{f.title}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )
          )}
        </>
      )}
    </Shell>
  );
}

function Shell({ children }) {
  return (
    <div>
      <AppNav />
      <main style={{ maxWidth: 920, margin: "0 auto", padding: "36px 24px 90px" }}>{children}</main>
    </div>
  );
}

function RunningState({ scan }) {
  return (
    <div style={{ position: "relative", overflow: "hidden", padding: "40px 28px", borderRadius: 18, border: `1px solid ${T.border}`, background: T.panel }}>
      <div style={{ position: "absolute", left: 0, right: 0, top: 0, height: 60, background: "linear-gradient(180deg, transparent, rgba(0,191,99,0.08), transparent)", animation: "scanSweep 3.2s linear infinite", pointerEvents: "none" }} />
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 18 }}>
        <span style={{ width: 9, height: 9, borderRadius: "50%", background: T.accent, animation: "blink 1s infinite" }} />
        <span style={{ fontFamily: T.mono, fontSize: 14, color: T.accentHi }}>Scanning {scan.target_url}…</span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
        <div style={{ flex: 1, height: 7, borderRadius: 999, background: "rgba(255,255,255,0.08)", overflow: "hidden" }}>
          <div style={{ width: `${scan.progress}%`, height: "100%", background: T.accent, transition: "width 0.5s" }} />
        </div>
        <span style={{ color: T.accent, fontFamily: T.mono, fontSize: 13, minWidth: 42 }}>{scan.progress}%</span>
      </div>
    </div>
  );
}

function ScoreRing({ score }) {
  const c = scoreColor(score);
  const r = 46, circ = 2 * Math.PI * r;
  const off = circ - (circ * (score ?? 0)) / 100;
  return (
    <div style={{ position: "relative", width: 120, height: 120 }}>
      <svg width="120" height="120" style={{ transform: "rotate(-90deg)" }}>
        <circle cx="60" cy="60" r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="9" />
        <circle cx="60" cy="60" r={r} fill="none" stroke={c} strokeWidth="9" strokeLinecap="round" strokeDasharray={circ} strokeDashoffset={off} style={{ transition: "stroke-dashoffset 0.8s ease" }} />
      </svg>
      <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
        <span style={{ fontFamily: T.heading, fontSize: 34, fontWeight: 800, color: c }}>{score ?? "—"}</span>
        <span style={{ fontSize: 11, color: T.muted, textTransform: "uppercase", letterSpacing: "0.08em" }}>Score</span>
      </div>
    </div>
  );
}

function FilterChip({ active, onClick, label, color }) {
  return (
    <button onClick={onClick} style={{ padding: "6px 13px", borderRadius: 999, cursor: "pointer", fontSize: 12.5, fontWeight: 600, fontFamily: T.body, border: `1px solid ${active ? color : T.border}`, background: active ? `${color}18` : "transparent", color: active ? color : T.muted }}>
      {label}
    </button>
  );
}

function FindingCard({ f, open, onToggle }) {
  const s = SEVERITY[f.severity];
  return (
    <div style={{ borderRadius: 14, border: `1px solid ${open ? s.border : T.border}`, background: "rgba(255,255,255,0.02)", overflow: "hidden" }}>
      <button onClick={onToggle} style={{ width: "100%", display: "flex", alignItems: "center", gap: 14, padding: "16px 18px", background: "none", border: "none", cursor: "pointer", textAlign: "left", fontFamily: T.body }}>
        <span style={{ fontSize: 10.5, fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", padding: "3px 9px", borderRadius: 999, color: s.color, border: `1px solid ${s.border}`, background: s.bg, minWidth: 60, textAlign: "center" }}>{s.label}</span>
        <span style={{ flex: 1, fontSize: 14.5, fontWeight: 600, color: T.text }}>
          {f.title}
          {f.is_new && <span style={{ marginLeft: 8, fontSize: 10, fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", padding: "2px 7px", borderRadius: 999, color: T.accentInk, background: T.accent }}>New</span>}
        </span>
        <span style={{ display: "flex", gap: 6, alignItems: "center" }}>
          {!f.passed && f.confidence && (() => { const c = CONF[f.confidence] || CONF.firm; return (
            <span title={`${c.label} — ${c.hint}`} style={{ fontSize: 9.5, fontWeight: 700, letterSpacing: "0.05em", textTransform: "uppercase", fontFamily: T.mono, color: c.color, border: `1px solid ${c.border}`, background: c.bg, borderRadius: 6, padding: "2px 6px" }}>{c.label}</span>
          ); })()}
          {f.owasp && <span style={{ fontSize: 10.5, fontWeight: 700, fontFamily: T.mono, color: T.accentHi, border: "1px solid rgba(0,191,99,0.3)", borderRadius: 6, padding: "2px 6px" }}>{f.owasp.split(":")[0]}</span>}
          {f.cwe && <span style={{ fontSize: 10.5, color: T.faint, fontFamily: T.mono }}>{f.cwe}</span>}
        </span>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={T.muted} strokeWidth="2" strokeLinecap="round" style={{ transform: open ? "rotate(180deg)" : "none", transition: "transform 0.2s" }}><path d="M6 9l6 6 6-6" /></svg>
      </button>
      {open && (
        <div style={{ padding: "4px 18px 20px 18px", display: "grid", gap: 14, borderTop: `1px solid ${T.border}` }}>
          {(f.owasp || f.cwe || f.layer) && (
            <Row label="Standards">
              <span style={{ display: "flex", gap: 8, flexWrap: "wrap", fontSize: 12.5 }}>
                {f.owasp && <span style={{ color: T.accentHi }}>{f.owasp} {OWASP_NAMES[f.owasp] || ""}</span>}
                {f.cwe && <span style={{ color: T.muted, fontFamily: T.mono }}>{f.cwe}</span>}
                {f.layer && <span style={{ color: T.faint }}>· {f.layer}</span>}
              </span>
            </Row>
          )}
          {!f.passed && (
            <Row label="Triage">
              <span style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center", fontSize: 12.5 }}>
                <span style={{ color: (CONF[f.confidence] || CONF.firm).color, fontWeight: 600 }}>{(CONF[f.confidence] || CONF.firm).label} confidence</span>
                <span style={{ color: T.faint }}>·</span>
                <span style={{ color: T.muted }}>Priority <b style={{ color: T.text, fontFamily: T.mono }}>{f.priority ?? 0}</b>/100</span>
                {f.evidence && /CISA KEV/i.test(f.evidence) && <span style={{ fontSize: 10.5, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em", color: "#f87171", border: "1px solid rgba(248,113,113,0.4)", background: "rgba(248,113,113,0.1)", borderRadius: 6, padding: "2px 7px" }}>KEV · exploited in the wild</span>}
              </span>
            </Row>
          )}
          <Row label="Affected URL"><code style={{ fontFamily: T.mono, fontSize: 13, color: T.accentHi, wordBreak: "break-all" }}>{f.url}</code></Row>
          {f.description && <Row label="Description"><p style={txt}>{f.description}</p></Row>}
          {f.impact && <Row label="Impact"><p style={txt}>{f.impact}</p></Row>}
          {f.evidence && <Row label="Evidence"><pre style={{ ...txt, fontFamily: T.mono, fontSize: 12.5, background: "rgba(0,0,0,0.35)", padding: "10px 12px", borderRadius: 8, overflow: "auto", margin: 0 }}>{f.evidence}</pre></Row>}
          {f.remediation && <Row label="How to fix"><p style={{ ...txt, color: T.accentHi }}>{f.remediation}</p></Row>}
        </div>
      )}
    </div>
  );
}

const txt = { fontSize: 13.5, lineHeight: 1.55, color: T.muted, margin: 0 };

function Row({ label, children }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "120px 1fr", gap: 14, alignItems: "start" }}>
      <span style={{ fontSize: 12, fontWeight: 600, color: T.faint, textTransform: "uppercase", letterSpacing: "0.05em", paddingTop: 2 }}>{label}</span>
      <div style={{ minWidth: 0 }}>{children}</div>
    </div>
  );
}

function Empty({ text }) {
  return <div style={{ textAlign: "center", padding: "56px 24px", color: T.muted, border: `1px dashed ${T.border}`, borderRadius: 14 }}>{text}</div>;
}
