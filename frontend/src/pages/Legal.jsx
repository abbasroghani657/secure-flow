import { Link, Outlet, useLocation } from "react-router-dom";
import { T } from "../theme";
import { MarketingNav, MarketingFooter } from "../components/marketing";

const LEGAL_TABS = [
  { path: "/legal/terms", label: "Terms of Service" },
  { path: "/legal/privacy", label: "Privacy Policy" },
  { path: "/legal/aup", label: "Acceptable Use Policy (AUP)" },
];

export default function LegalLayout() {
  const { pathname } = useLocation();

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column", background: T.bg }}>
      <MarketingNav />
      <div style={{ flex: 1, maxWidth: 1040, margin: "0 auto", padding: "60px 28px", display: "flex", gap: 40, width: "100%" }}>
        
        <aside style={{ width: 240, flexShrink: 0 }}>
          <div style={{ position: "sticky", top: 100 }}>
            <h3 style={{ fontSize: 13, textTransform: "uppercase", letterSpacing: "0.06em", color: T.muted, marginBottom: 16 }}>Legal</h3>
            <nav style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              {LEGAL_TABS.map(tab => {
                const active = pathname.startsWith(tab.path);
                return (
                  <Link
                    key={tab.path}
                    to={tab.path}
                    style={{
                      padding: "8px 12px",
                      borderRadius: 6,
                      fontSize: 14.5,
                      fontWeight: active ? 600 : 400,
                      color: active ? T.text : T.muted,
                      background: active ? "rgba(255,255,255,0.05)" : "transparent",
                      textDecoration: "none"
                    }}
                  >
                    {tab.label}
                  </Link>
                );
              })}
            </nav>
          </div>
        </aside>

        <main style={{ flex: 1, background: "rgba(255,255,255,0.02)", border: `1px solid ${T.border}`, borderRadius: 16, padding: "40px 48px", color: T.text, lineHeight: 1.7 }}>
          <Outlet />
        </main>
      </div>
      <MarketingFooter />
    </div>
  );
}

export function Terms() {
  return (
    <div>
      <h1 style={{ fontSize: 32, marginBottom: 24 }}>Terms of Service</h1>
      <p style={{ color: T.muted }}>Last updated: Jan 2026</p>
      <h3>1. Agreement to Terms</h3>
      <p>By accessing Pentrixa, you agree to be bound by these Terms. If you disagree, do not use the service.</p>
      <h3>2. Acceptable Use</h3>
      <p>You agree to comply with our Acceptable Use Policy (AUP). Unauthorized scanning of third-party infrastructure is strictly prohibited.</p>
      <h3>3. Liability</h3>
      <p>Pentrixa is provided "as is". We are not liable for any damages arising from your use of the platform or the resulting vulnerability reports.</p>
    </div>
  );
}

export function Privacy() {
  return (
    <div>
      <h1 style={{ fontSize: 32, marginBottom: 24 }}>Privacy Policy</h1>
      <p style={{ color: T.muted }}>Last updated: Jan 2026</p>
      <h3>1. Data Collection</h3>
      <p>We collect your email address for authentication and billing. We do not sell your personal data.</p>
      <h3>2. Scan Data</h3>
      <p>Source code and binaries uploaded for scanning are analyzed in memory and immediately destroyed. We retain the metadata (findings) indefinitely unless you request deletion.</p>
      <h3>3. Telemetry</h3>
      <p>We use essential cookies for sessions and rate-limiting.</p>
    </div>
  );
}

export function AUP() {
  return (
    <div>
      <h1 style={{ fontSize: 32, marginBottom: 24 }}>Acceptable Use Policy</h1>
      <p style={{ color: T.muted }}>Last updated: Jan 2026</p>
      <div style={{ padding: 16, background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)", borderRadius: 8, color: "#ef4444", marginBottom: 24 }}>
        <strong>CRITICAL:</strong> Violation of the AUP will result in an immediate, permanent ban and potential reporting to law enforcement.
      </div>
      <h3>1. Authorization Requirement</h3>
      <p>You may only initiate scans against infrastructure (URLs, IP addresses, APIs, or source code) that you explicitly own, or have explicit written permission to test.</p>
      <h3>2. Prohibited Targets</h3>
      <p>You may not scan governmental (.gov), military (.mil), or critical infrastructure unless operating under a verified bug bounty program.</p>
      <h3>3. Abuse</h3>
      <p>Using Pentrixa to conduct DDoS attacks, exfiltrate data, or deploy malware is strictly prohibited.</p>
    </div>
  );
}
