import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api } from "../api";
import { computeCompliance, FRAMEWORKS } from "../compliance";

// A print-optimised, light-themed security assessment report.
// "Print / Save as PDF" turns it into a shareable client deliverable.

const SEV = {
  critical: { label: "Critical", color: "#B91C1C", bg: "#FEE2E2" },
  high: { label: "High", color: "#C2410C", bg: "#FFEDD5" },
  medium: { label: "Medium", color: "#B45309", bg: "#FEF3C7" },
  low: { label: "Low", color: "#1D4ED8", bg: "#DBEAFE" },
  info: { label: "Info", color: "#374151", bg: "#F3F4F6" },
};
const ORDER = ["critical", "high", "medium", "low", "info"];

function riskLevel(scan) {
  if (scan.critical_count > 0) return { label: "Critical risk", color: "#B91C1C" };
  if (scan.high_count > 0) return { label: "High risk", color: "#C2410C" };
  if (scan.medium_count > 0) return { label: "Medium risk", color: "#B45309" };
  if (scan.low_count > 0) return { label: "Low risk", color: "#1D4ED8" };
  return { label: "Minimal risk", color: "#047857" };
}

function scoreColor(s) {
  if (s == null) return "#6B7280";
  if (s >= 80) return "#047857";
  if (s >= 50) return "#B45309";
  return "#B91C1C";
}

export default function Report() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    api.getScan(id).then(setScan).catch((e) => setErr(e.message));
  }, [id]);

  if (err) return <Center>{err}</Center>;
  if (!scan) return <Center>Loading report…</Center>;
  if (scan.status !== "completed") return <Center>This scan has no completed report yet.</Center>;

  const issues = (scan.findings || []).filter((f) => !f.passed);
  const passed = (scan.findings || []).filter((f) => f.passed);
  const risk = riskLevel(scan);
  const counts = { critical: scan.critical_count, high: scan.high_count, medium: scan.medium_count, low: scan.low_count, info: scan.info_count };

  const compliance = {};
  for (const f of issues) (compliance[f.compliance_ref || "Unmapped"] ??= []).push(f);
  const frameworks = computeCompliance(issues);

  return (
    <>
      <style>{`
        @media print { .no-print { display: none !important; } .report { box-shadow: none !important; margin: 0 !important; } body { background: #fff !important; } .finding { break-inside: avoid; } .sec { break-inside: avoid-page; } }
        @page { margin: 18mm 14mm; }
      `}</style>
      <div style={{ background: "#E5E7EB", minHeight: "100vh", padding: "24px 16px", fontFamily: "Inter, system-ui, sans-serif", color: "#111827" }}>
        <div className="no-print" style={{ maxWidth: 820, margin: "0 auto 16px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <Link to={`/scans/${id}`} style={{ color: "#374151", fontSize: 14, textDecoration: "none" }}>← Back to scan</Link>
          <button onClick={() => window.print()} style={{ background: "#00BF63", color: "#06130B", border: "none", padding: "10px 20px", borderRadius: 8, fontSize: 14, fontWeight: 600, cursor: "pointer" }}>
            Print / Save as PDF
          </button>
        </div>

        <div className="report" style={{ maxWidth: 820, margin: "0 auto", background: "#fff", padding: "48px 52px", boxShadow: "0 8px 30px rgba(0,0,0,0.12)", borderRadius: 4 }}>
          {/* Header */}
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", borderBottom: "2px solid #111827", paddingBottom: 18, marginBottom: 28 }}>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 700, fontSize: 20, fontFamily: "Outfit, sans-serif" }}>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#00A855" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="M9 12l2 2 4-4" /></svg>
                Secure<span style={{ color: "#00A855" }}>Flow</span>
              </div>
              <div style={{ fontSize: 13, color: "#6B7280", marginTop: 4 }}>Security Assessment Report</div>
            </div>
            <div style={{ textAlign: "right", fontSize: 12, color: "#6B7280" }}>
              <div>Report generated</div>
              <div style={{ fontWeight: 600, color: "#111827" }}>{new Date().toLocaleString()}</div>
            </div>
          </div>

          {/* Target meta */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 28, fontSize: 13.5 }}>
            <Meta label="Target">{scan.target_url}</Meta>
            <Meta label="Scan type">{scan.scan_type}</Meta>
            <Meta label="Scan started">{scan.started_at ? new Date(scan.started_at).toLocaleString() : "—"}</Meta>
            <Meta label="Scan completed">{scan.finished_at ? new Date(scan.finished_at).toLocaleString() : "—"}</Meta>
          </div>

          {/* Executive summary */}
          <div className="sec" style={{ display: "flex", gap: 24, alignItems: "center", padding: "22px 24px", background: "#F9FAFB", border: "1px solid #E5E7EB", borderRadius: 8, marginBottom: 30 }}>
            <div style={{ textAlign: "center", paddingRight: 24, borderRight: "1px solid #E5E7EB" }}>
              <div style={{ fontSize: 44, fontWeight: 800, fontFamily: "Outfit, sans-serif", color: scoreColor(scan.security_score), lineHeight: 1 }}>{scan.security_score}</div>
              <div style={{ fontSize: 11, color: "#6B7280", textTransform: "uppercase", letterSpacing: "0.06em", marginTop: 4 }}>Security score</div>
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ display: "inline-block", padding: "3px 10px", borderRadius: 999, fontSize: 12, fontWeight: 700, color: "#fff", background: risk.color, marginBottom: 8 }}>{risk.label}</div>
              <p style={{ margin: 0, fontSize: 13.5, color: "#374151", lineHeight: 1.5 }}>
                This assessment identified <b>{issues.length}</b> issue{issues.length !== 1 ? "s" : ""} across the target
                {scan.critical_count + scan.high_count > 0
                  ? `, including ${scan.critical_count + scan.high_count} high-severity or critical finding(s) that should be remediated promptly.`
                  : ". No critical or high-severity issues were found."}
              </p>
            </div>
          </div>

          {/* Severity breakdown */}
          <div className="sec" style={{ display: "grid", gridTemplateColumns: "repeat(5,1fr)", gap: 10, marginBottom: 34 }}>
            {ORDER.map((s) => (
              <div key={s} style={{ textAlign: "center", padding: "12px 6px", border: `1px solid ${SEV[s].color}33`, background: SEV[s].bg, borderRadius: 8 }}>
                <div style={{ fontSize: 24, fontWeight: 800, fontFamily: "Outfit, sans-serif", color: SEV[s].color }}>{counts[s]}</div>
                <div style={{ fontSize: 10.5, color: "#6B7280", textTransform: "uppercase", letterSpacing: "0.05em" }}>{SEV[s].label}</div>
              </div>
            ))}
          </div>

          {/* Findings */}
          <SectionTitle n={issues.length}>Findings</SectionTitle>
          {issues.length === 0 ? (
            <p style={{ color: "#6B7280", fontSize: 14 }}>No issues were identified.</p>
          ) : (
            <div style={{ display: "grid", gap: 14, marginBottom: 34 }}>
              {issues.map((f, i) => (
                <div key={f.id} className="finding" style={{ border: "1px solid #E5E7EB", borderRadius: 8, overflow: "hidden" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "12px 16px", background: "#F9FAFB", borderBottom: "1px solid #E5E7EB" }}>
                    <span style={{ fontSize: 10.5, fontWeight: 700, textTransform: "uppercase", padding: "3px 8px", borderRadius: 4, color: SEV[f.severity].color, background: SEV[f.severity].bg }}>{SEV[f.severity].label}</span>
                    <span style={{ fontWeight: 600, fontSize: 14.5 }}>{i + 1}. {f.title}</span>
                    <span style={{ marginLeft: "auto", fontSize: 11.5, color: "#6B7280", fontFamily: "'JetBrains Mono', monospace" }}>{f.compliance_ref}</span>
                  </div>
                  <div style={{ padding: "14px 16px", display: "grid", gap: 10, fontSize: 13 }}>
                    <Row label="Affected">{f.url}</Row>
                    {f.description && <Row label="Description">{f.description}</Row>}
                    {f.impact && <Row label="Impact">{f.impact}</Row>}
                    {f.evidence && <Row label="Evidence"><code style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "#374151" }}>{f.evidence}</code></Row>}
                    {f.remediation && <Row label="Remediation"><span style={{ color: "#047857", fontWeight: 500 }}>{f.remediation}</span></Row>}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Compliance */}
          {Object.keys(compliance).length > 0 && (
            <>
              <SectionTitle>Compliance summary</SectionTitle>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13, marginBottom: 34 }}>
                <thead>
                  <tr style={{ textAlign: "left", borderBottom: "2px solid #E5E7EB" }}>
                    <th style={{ padding: "8px 10px", color: "#6B7280", fontWeight: 600 }}>Framework / control</th>
                    <th style={{ padding: "8px 10px", color: "#6B7280", fontWeight: 600, width: 90 }}>Issues</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(compliance).sort((a, b) => b[1].length - a[1].length).map(([ref, items]) => (
                    <tr key={ref} style={{ borderBottom: "1px solid #F3F4F6" }}>
                      <td style={{ padding: "8px 10px" }}>{ref}</td>
                      <td style={{ padding: "8px 10px", fontWeight: 600 }}>{items.length}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}

          {/* Compliance framework mapping */}
          <div className="sec" style={{ marginBottom: 34 }}>
            <SectionTitle>Compliance framework mapping</SectionTitle>
            <p style={{ margin: "0 0 12px", fontSize: 12.5, color: "#6B7280" }}>
              Findings mapped to the controls they affect in each framework. "Gaps" is the number of findings touching that framework.
            </p>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
              <thead>
                <tr style={{ textAlign: "left", borderBottom: "2px solid #E5E7EB" }}>
                  <th style={{ padding: "8px 10px", color: "#6B7280", fontWeight: 600, width: 130 }}>Framework</th>
                  <th style={{ padding: "8px 10px", color: "#6B7280", fontWeight: 600, width: 70 }}>Status</th>
                  <th style={{ padding: "8px 10px", color: "#6B7280", fontWeight: 600 }}>Affected controls</th>
                </tr>
              </thead>
              <tbody>
                {FRAMEWORKS.map((fw) => {
                  const d = frameworks[fw];
                  const clean = d.gaps === 0;
                  return (
                    <tr key={fw} style={{ borderBottom: "1px solid #F3F4F6", verticalAlign: "top" }}>
                      <td style={{ padding: "8px 10px", fontWeight: 600 }}>{fw}</td>
                      <td style={{ padding: "8px 10px", fontWeight: 700, color: clean ? "#047857" : "#B91C1C", whiteSpace: "nowrap" }}>
                        {clean ? "✓ Pass" : `${d.gaps} gap${d.gaps !== 1 ? "s" : ""}`}
                      </td>
                      <td style={{ padding: "8px 10px", color: "#374151" }}>
                        {clean ? "No mapped findings" : [...d.controls].join(" · ")}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Passed */}
          {passed.length > 0 && (
            <>
              <SectionTitle n={passed.length}>Controls passed</SectionTitle>
              <ul style={{ margin: "0 0 30px", paddingLeft: 20, fontSize: 13, color: "#374151", columns: 2, gap: 20 }}>
                {passed.map((f) => <li key={f.id} style={{ marginBottom: 5 }}>{f.title}</li>)}
              </ul>
            </>
          )}

          {/* Footer */}
          <div style={{ borderTop: "1px solid #E5E7EB", paddingTop: 16, fontSize: 11, color: "#9CA3AF", lineHeight: 1.5 }}>
            <b>Confidential.</b> This report was generated by SecureFlow for the verified owner of {scan.target_url}. It reflects a passive, point-in-time assessment and does not guarantee the absence of other vulnerabilities. Authorised use only.
          </div>
        </div>
      </div>
    </>
  );
}

function Center({ children }) {
  return <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", color: "#374151", fontFamily: "Inter, sans-serif" }}>{children}</div>;
}
function Meta({ label, children }) {
  return (
    <div>
      <div style={{ fontSize: 11, color: "#9CA3AF", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 3 }}>{label}</div>
      <div style={{ fontWeight: 600, fontFamily: "'JetBrains Mono', monospace", fontSize: 13, wordBreak: "break-all" }}>{children}</div>
    </div>
  );
}
function SectionTitle({ children, n }) {
  return (
    <h2 style={{ fontFamily: "Outfit, sans-serif", fontSize: 18, fontWeight: 700, margin: "0 0 14px", display: "flex", alignItems: "center", gap: 8 }}>
      {children}{n != null && <span style={{ fontSize: 13, fontWeight: 500, color: "#9CA3AF" }}>({n})</span>}
    </h2>
  );
}
function Row({ label, children }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "100px 1fr", gap: 12 }}>
      <span style={{ fontSize: 11, fontWeight: 600, color: "#9CA3AF", textTransform: "uppercase", letterSpacing: "0.04em", paddingTop: 1 }}>{label}</span>
      <span style={{ color: "#374151", lineHeight: 1.5, wordBreak: "break-word" }}>{children}</span>
    </div>
  );
}
