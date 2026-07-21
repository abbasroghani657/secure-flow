import { Component } from "react";
import { T } from "../theme";

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}>
        <div style={{ maxWidth: 460, textAlign: "center" }}>
          <h1 style={{ fontFamily: T.heading, fontSize: 26, fontWeight: 700, margin: "0 0 10px" }}>Something went wrong</h1>
          <p style={{ color: T.muted, fontSize: 14.5, margin: "0 0 22px" }}>
            An unexpected error occurred while rendering this page.
          </p>
          <div style={{ display: "flex", gap: 10, justifyContent: "center" }}>
            <button onClick={() => this.setState({ error: null })} style={{ background: "none", border: `1px solid ${T.borderStrong}`, color: T.text, padding: "10px 18px", borderRadius: 10, cursor: "pointer", fontFamily: T.body, fontSize: 14 }}>
              Try again
            </button>
            <a href="/" style={{ background: T.accent, color: T.accentInk, padding: "10px 18px", borderRadius: 10, fontSize: 14, fontWeight: 600 }}>Go home</a>
          </div>
          {import.meta.env.DEV && (
            <pre style={{ marginTop: 24, textAlign: "left", fontFamily: T.mono, fontSize: 12, color: "#F87171", background: "rgba(0,0,0,0.35)", padding: 14, borderRadius: 8, overflow: "auto" }}>
              {String(this.state.error?.stack || this.state.error)}
            </pre>
          )}
        </div>
      </div>
    );
  }
}
