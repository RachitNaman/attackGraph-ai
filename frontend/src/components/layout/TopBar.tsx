import { T } from "../../lib/designTokens";

export function TopBar() {
  return (
    <header style={{ height: 44, background: T.bg1, borderBottom: `1px solid ${T.border}`, display: "flex", alignItems: "center", padding: "0 20px", gap: 16, flexShrink: 0 }}>
      <div style={{ fontSize: 13, fontWeight: 600, color: T.text0, letterSpacing: "0.02em" }}>AttackGraph</div>
      <div style={{ fontSize: 10, color: T.text2, fontFamily: "'IBM Plex Mono', monospace" }}>AI</div>
      <div style={{ flex: 1 }} />
      {["Neo4j", "Qdrant", "Gemini"].map((label) => (
        <div key={label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#3db864" }} />
          <span style={{ fontSize: 10, color: T.text2 }}>{label}</span>
        </div>
      ))}
    </header>
  );
}
