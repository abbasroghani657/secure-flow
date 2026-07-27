import { useEffect, useRef, useState } from "react";
import { T } from "../theme";

// Tag palette, semantic, matches the findings colours used across the app.
const TAG = {
  INFO: "#60A5FA",
  PASS: T.accent,
  LOW: "#60A5FA",
  MED: "#FBBF24",
  HIGH: "#FB923C",
  CRIT: "#F87171",
};

// A realistic scan transcript that streams line by line.
const LINES = [
  ["INFO", "Fingerprinting stack, nginx 1.24, Next.js 14, PostgreSQL"],
  ["PASS", "TLS 1.3 configured, HSTS present"],
  ["INFO", "Crawled 214 endpoints, 38 forms, 12 API routes"],
  ["MED", "Missing Content-Security-Policy header on 214 pages"],
  ["PASS", "No exposed .git / .env directories"],
  ["HIGH", "SQL injection in /search?q= (error-based)"],
  ["INFO", "Checking dependencies against OSV, 8 ecosystems"],
  ["LOW", "Cookie 'sid' missing SameSite attribute"],
  ["CRIT", "Hardcoded AWS key in /assets/app.min.js"],
  ["INFO", "Cross-referencing CISA KEV + EPSS for priority"],
];

export default function ScanTerminal() {
  const [shown, setShown] = useState(0);
  const [pct, setPct] = useState(0);
  const [done, setDone] = useState(false);
  const boxRef = useRef(null);

  useEffect(() => {
    let lineTimer, pctTimer, resetTimer;
    let cancelled = false;

    function run() {
      if (cancelled) return;
      setShown(0); setPct(0); setDone(false);
      let i = 0;
      lineTimer = setInterval(() => {
        i += 1;
        setShown(i);
        if (i >= LINES.length) {
          clearInterval(lineTimer);
          setTimeout(() => !cancelled && setDone(true), 700);
        }
      }, 620);
      // progress bar creeps toward ~96% while scanning, snaps to 100 when done
      pctTimer = setInterval(() => {
        setPct((p) => (p >= 96 ? 96 : p + Math.max(1, Math.round((96 - p) / 14))));
      }, 260);
      // restart the loop so the hero is always alive
      resetTimer = setTimeout(run, LINES.length * 620 + 5200);
    }
    run();
    return () => { cancelled = true; clearInterval(lineTimer); clearInterval(pctTimer); clearTimeout(resetTimer); };
  }, []);

  useEffect(() => { if (done) setPct(100); }, [done]);
  useEffect(() => { if (boxRef.current) boxRef.current.scrollTop = boxRef.current.scrollHeight; }, [shown]);

  return (
    <div style={{
      position: "relative", borderRadius: 14, overflow: "hidden",
      border: `1px solid ${T.borderStrong}`,
      background: "linear-gradient(180deg, #0C1218, #0A0E12)",
      boxShadow: "0 30px 80px -20px rgba(0,0,0,0.6), 0 0 0 1px rgba(6,182,212,0.06)",
      fontFamily: T.mono,
    }}>
      {/* window bar */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "12px 16px", borderBottom: `1px solid ${T.border}`, background: "rgba(255,255,255,0.02)" }}>
        <span style={{ width: 11, height: 11, borderRadius: "50%", background: "#FF5F57" }} />
        <span style={{ width: 11, height: 11, borderRadius: "50%", background: "#FEBC2E" }} />
        <span style={{ width: 11, height: 11, borderRadius: "50%", background: "#28C840" }} />
        <span style={{ marginLeft: 10, fontSize: 12.5, color: T.muted }}>pentrixa scan, acme-store.com</span>
        <span style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 7, fontSize: 11.5, fontWeight: 700, letterSpacing: "0.08em", color: done ? T.accent : T.accentHi }}>
          <span style={{ width: 7, height: 7, borderRadius: "50%", background: done ? T.accent : T.accentHi, animation: done ? "none" : "blink 1.2s infinite" }} />
          {done ? "COMPLETE" : "SCANNING"}
        </span>
      </div>

      {/* progress */}
      <div style={{ padding: "16px 16px 6px", display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ flex: 1, height: 7, borderRadius: 99, background: "rgba(255,255,255,0.07)", overflow: "hidden" }}>
          <div style={{ height: "100%", width: `${pct}%`, borderRadius: 99, background: `linear-gradient(90deg, ${T.accent}, ${T.accentHi})`, transition: "width 0.4s ease", boxShadow: `0 0 12px ${T.accent}` }} />
        </div>
        <span style={{ fontSize: 12.5, fontWeight: 600, color: T.accentHi, fontVariantNumeric: "tabular-nums", minWidth: 38, textAlign: "right" }}>{pct}%</span>
      </div>

      {/* stream */}
      <div ref={boxRef} style={{ padding: "10px 16px 20px", display: "grid", gap: 9, minHeight: 232, maxHeight: 232, overflow: "hidden" }}>
        {LINES.slice(0, shown).map(([tag, text], i) => (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 12, animation: "fadeUp 0.35s ease both", fontSize: 13.5 }}>
            <span style={{ flex: "none", minWidth: 46, textAlign: "center", fontSize: 10.5, fontWeight: 800, letterSpacing: "0.06em", color: TAG[tag], border: `1px solid ${TAG[tag]}55`, background: `${TAG[tag]}18`, borderRadius: 999, padding: "3px 0" }}>{tag}</span>
            <span style={{ color: tag === "PASS" || tag === "INFO" ? T.muted : T.text }}>{text}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
