// Design tokens lifted from the SecureFlow mockups (dark, green accent).
export const T = {
  bg: "#0D0F0D",
  panel: "#121412",
  panel2: "#161916",
  text: "#F3F6FA",
  muted: "#A7B0BC",
  faint: "#6B7280",
  accent: "#00BF63",
  accentHi: "#33D98A",
  accentInk: "#06130B",
  border: "rgba(255,255,255,0.08)",
  borderStrong: "rgba(255,255,255,0.14)",
  heading: "Outfit, sans-serif",
  body: "Inter, sans-serif",
  mono: "'JetBrains Mono', monospace",
};

export const SEVERITY = {
  critical: { color: "#F87171", bg: "rgba(220,38,38,0.12)", border: "rgba(248,113,113,0.4)", label: "Critical" },
  high: { color: "#FB923C", bg: "rgba(234,88,12,0.12)", border: "rgba(251,146,60,0.4)", label: "High" },
  medium: { color: "#FBBF24", bg: "rgba(217,119,6,0.12)", border: "rgba(251,191,36,0.4)", label: "Medium" },
  low: { color: "#60A5FA", bg: "rgba(37,99,235,0.12)", border: "rgba(96,165,250,0.4)", label: "Low" },
  info: { color: "#9CA3AF", bg: "rgba(107,114,128,0.12)", border: "rgba(156,163,175,0.4)", label: "Info" },
};

export function scoreColor(score) {
  if (score == null) return T.muted;
  if (score >= 80) return T.accent;
  if (score >= 50) return "#FBBF24";
  return "#F87171";
}
