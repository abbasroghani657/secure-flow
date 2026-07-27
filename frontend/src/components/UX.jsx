import { createContext, useCallback, useContext, useRef, useState } from "react";
import { T } from "../theme";

// One provider for the two bits of feedback every app needs and this one was
// missing: transient toasts, and a real confirm dialog instead of window.confirm().
const UXCtx = createContext(null);

let _id = 0;

export function UXProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const [dialog, setDialog] = useState(null); // { opts, resolve }
  const resolver = useRef(null);

  const dismiss = useCallback((id) => setToasts((t) => t.filter((x) => x.id !== id)), []);

  const toast = useCallback((message, type = "success", ttl = 3800) => {
    const id = ++_id;
    setToasts((t) => [...t, { id, message, type }]);
    if (ttl) setTimeout(() => dismiss(id), ttl);
    return id;
  }, [dismiss]);

  const confirm = useCallback((opts) => {
    return new Promise((resolve) => {
      resolver.current = resolve;
      setDialog({ opts: typeof opts === "string" ? { message: opts } : opts });
    });
  }, []);

  const settle = useCallback((value) => {
    resolver.current?.(value);
    resolver.current = null;
    setDialog(null);
  }, []);

  return (
    <UXCtx.Provider value={{ toast, confirm }}>
      {children}
      <ToastStack toasts={toasts} onDismiss={dismiss} />
      {dialog && <ConfirmDialog opts={dialog.opts} onResolve={settle} />}
    </UXCtx.Provider>
  );
}

export function useUX() {
  const ctx = useContext(UXCtx);
  if (!ctx) throw new Error("useUX must be used inside <UXProvider>");
  return ctx;
}

const TOAST_STYLES = {
  success: { accent: T.accent, icon: <path d="M20 6L9 17l-5-5" /> },
  error: { accent: "#F87171", icon: <><path d="M18 6L6 18" /><path d="M6 6l12 12" /></> },
  info: { accent: "#60A5FA", icon: <><path d="M12 16v-4" /><path d="M12 8h.01" /></> },
};

function ToastStack({ toasts, onDismiss }) {
  return (
    <div style={{ position: "fixed", top: 18, right: 18, zIndex: 1000, display: "flex", flexDirection: "column", gap: 10, maxWidth: "calc(100vw - 36px)" }}>
      {toasts.map((t) => {
        const s = TOAST_STYLES[t.type] || TOAST_STYLES.info;
        return (
          <div key={t.id} role="status" style={{ display: "flex", alignItems: "center", gap: 12, minWidth: 260, maxWidth: 380, padding: "13px 15px", borderRadius: 12, background: "rgba(15,20,26,0.96)", border: `1px solid ${T.borderStrong}`, borderLeft: `3px solid ${s.accent}`, boxShadow: "0 12px 34px rgba(0,0,0,0.45)", backdropFilter: "blur(8px)", animation: "toastIn 0.28s cubic-bezier(0.2,0.8,0.2,1)" }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={s.accent} strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "none" }}>{s.icon}</svg>
            <span style={{ flex: 1, fontSize: 13.5, color: T.text, lineHeight: 1.45 }}>{t.message}</span>
            <button onClick={() => onDismiss(t.id)} aria-label="Dismiss" style={{ background: "none", border: "none", color: T.faint, cursor: "pointer", padding: 2, display: "flex" }}>
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M18 6L6 18M6 6l12 12" /></svg>
            </button>
          </div>
        );
      })}
    </div>
  );
}

function ConfirmDialog({ opts, onResolve }) {
  const { title = "Are you sure?", message = "", confirmLabel = "Confirm", cancelLabel = "Cancel", danger = false } = opts;
  const accent = danger ? "#F87171" : T.accent;
  return (
    <div
      onClick={() => onResolve(false)}
      style={{ position: "fixed", inset: 0, zIndex: 1001, display: "flex", alignItems: "center", justifyContent: "center", padding: 20, background: "rgba(4,8,11,0.6)", backdropFilter: "blur(4px)", animation: "fadeUp 0.18s ease" }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        role="dialog" aria-modal="true"
        style={{ width: "100%", maxWidth: 420, background: T.panel, border: `1px solid ${T.borderStrong}`, borderRadius: 18, padding: "26px 26px 22px", boxShadow: "0 24px 60px rgba(0,0,0,0.5)", animation: "toastIn 0.24s cubic-bezier(0.2,0.8,0.2,1)" }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
          <span style={{ width: 38, height: 38, borderRadius: 10, flex: "none", display: "flex", alignItems: "center", justifyContent: "center", background: `${accent}18`, border: `1px solid ${accent}55` }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={accent} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              {danger ? <><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z" /><path d="M12 9v4" /><path d="M12 17h.01" /></> : <><circle cx="12" cy="12" r="10" /><path d="M12 16v-4" /><path d="M12 8h.01" /></>}
            </svg>
          </span>
          <h2 style={{ fontFamily: T.heading, fontSize: 19, fontWeight: 700, margin: 0 }}>{title}</h2>
        </div>
        {message && <p style={{ fontSize: 14, lineHeight: 1.6, color: T.muted, margin: "0 0 22px" }}>{message}</p>}
        <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
          <button onClick={() => onResolve(false)} style={{ background: "none", border: `1px solid ${T.borderStrong}`, color: T.text, fontFamily: T.body, fontSize: 14, fontWeight: 600, padding: "9px 18px", borderRadius: 10, cursor: "pointer" }}>{cancelLabel}</button>
          <button autoFocus onClick={() => onResolve(true)} style={{ background: accent, border: "none", color: danger ? "#fff" : T.accentInk, fontFamily: T.body, fontSize: 14, fontWeight: 700, padding: "9px 18px", borderRadius: 10, cursor: "pointer" }}>{confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}
