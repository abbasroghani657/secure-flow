import { T } from "../theme";

// Lucide-style line icons, distinct per concept so nothing looks stamped out.
const PATHS = {
  globe: <><circle cx="12" cy="12" r="9" /><path d="M3 12h18" /><path d="M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18Z" /></>,
  smartphone: <><rect x="6" y="2" width="12" height="20" rx="2.5" /><path d="M11 18h2" /></>,
  cloud: <><path d="M17.5 19a4.5 4.5 0 0 0 .5-8.98A6 6 0 0 0 6.2 9.4 4.5 4.5 0 0 0 7 18.99" /><path d="M9 19h8.5" /></>,
  code: <><path d="m16 18 5-6-5-6" /><path d="m8 6-5 6 5 6" /><path d="m13.5 4-3 16" /></>,
  package: <><path d="M12 3 3 8v8l9 5 9-5V8Z" /><path d="m3 8 9 5 9-5" /><path d="M12 13v8" /></>,
  target: <><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="5" /><circle cx="12" cy="12" r="1.4" /></>,
  shield: <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="m9 12 2 2 4-4" /></>,
  search: <><circle cx="11" cy="11" r="7" /><path d="m21 21-4.3-4.3" /></>,
  gauge: <><path d="m12 14 4-4" /><path d="M3.34 19a10 10 0 1 1 17.32 0" /></>,
  bolt: <><path d="M13 2 4.5 13.5H12l-1 8.5L19.5 10H12l1-8Z" /></>,
  lock: <><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /></>,
  file: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><path d="M14 2v6h6" /></>,
};

export function Icon({ name, size = 20, color = "currentColor", stroke = 1.6 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth={stroke} strokeLinecap="round" strokeLinejoin="round">
      {PATHS[name] || PATHS.shield}
    </svg>
  );
}

// A tinted rounded icon frame, still varied by icon inside.
export function IconBadge({ name, size = 44 }) {
  return (
    <span style={{ width: size, height: size, borderRadius: 12, flex: "none", background: "rgba(6,182,212,0.1)", border: "1px solid rgba(6,182,212,0.25)", display: "inline-flex", alignItems: "center", justifyContent: "center" }}>
      <Icon name={name} size={Math.round(size * 0.46)} color={T.accent} stroke={1.7} />
    </span>
  );
}
