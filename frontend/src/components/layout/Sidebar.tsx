import { T } from "../../lib/designTokens";

const items = [
  { id: "graph", label: "Attack Graph", icon: "AG" },
  { id: "analysis", label: "AI Analysis", icon: "AI" },
  { id: "vulns", label: "Vulnerabilities", icon: "V" },
  { id: "assets", label: "Assets", icon: "O" },
];

export function Sidebar({
  activeView,
  setActiveView,
}: {
  activeView: string;
  setActiveView: (view: string) => void;
}) {
  return (
    <nav style={{ width: 56, background: T.bg1, borderRight: `1px solid ${T.border}`, display: "flex", flexDirection: "column", alignItems: "center", padding: "16px 0", gap: 4, flexShrink: 0 }}>
      <div style={{ width: 28, height: 28, background: T.accent, borderRadius: 6, display: "flex", alignItems: "center", justifyContent: "center", marginBottom: 20 }}>
        <span style={{ color: "#fff", fontSize: 14, fontWeight: 700 }}>A</span>
      </div>
      {items.map((item) => (
        <button
          key={item.id}
          onClick={() => setActiveView(item.id)}
          title={item.label}
          type="button"
          style={{ width: 36, height: 36, border: "none", borderRadius: 7, cursor: "pointer", background: activeView === item.id ? T.bg4 : "transparent", color: activeView === item.id ? T.text0 : T.text2, fontSize: 11, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center", transition: "all 0.15s" }}
        >
          {item.icon}
        </button>
      ))}
    </nav>
  );
}
