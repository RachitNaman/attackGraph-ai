import { useRef, useState } from "react";
import { T } from "../../lib/designTokens";

const EXAMPLE_QUERIES = [
  "How can an attacker reach the database?",
  "What is the blast radius if web-server-01 is compromised?",
  "Show all privilege escalation paths to root",
  "Which vulnerabilities need immediate patching?",
];

export function QueryPanel({
  onAnalyze,
  loading,
}: {
  onAnalyze: (query: string) => void;
  loading: boolean;
}) {
  const [query, setQuery] = useState("How can an attacker reach the database?");
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);

  return (
    <div style={{ padding: "16px", borderBottom: `1px solid ${T.border}` }}>
      <div style={{ fontSize: 10, color: T.text2, textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 10, fontWeight: 600 }}>
        AI ATTACK ANALYSIS
      </div>
      <textarea
        ref={textareaRef}
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        rows={2}
        style={{ width: "100%", background: T.bg3, border: `1px solid ${T.border2}`, borderRadius: 6, padding: "10px 12px", color: T.text0, fontSize: 13, fontFamily: "'IBM Plex Sans', sans-serif", resize: "none", outline: "none", boxSizing: "border-box", lineHeight: 1.5 }}
        placeholder="Ask about attack paths, vulnerabilities, risk..."
      />
      <div style={{ marginTop: 8, display: "flex", gap: 6 }}>
        <button
          onClick={() => onAnalyze(query)}
          disabled={loading}
          style={{ flex: 1, background: loading ? T.bg3 : T.accent, border: "none", borderRadius: 6, padding: "8px 0", color: loading ? T.text2 : "#fff", fontSize: 12, fontWeight: 600, cursor: loading ? "not-allowed" : "pointer", transition: "background 0.15s" }}
          type="button"
        >
          {loading ? "Analyzing..." : "Run Analysis"}
        </button>
      </div>
      <div style={{ marginTop: 10 }}>
        <div style={{ fontSize: 9, color: T.text3, marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.08em" }}>Example queries</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
          {EXAMPLE_QUERIES.map((item) => (
            <button
              key={item}
              onClick={() => setQuery(item)}
              style={{ background: "none", border: "none", textAlign: "left", color: T.text2, fontSize: 10, cursor: "pointer", padding: "3px 0 3px 8px", fontFamily: "'IBM Plex Sans', sans-serif", lineHeight: 1.4, borderLeft: `2px solid ${T.border2}` }}
              type="button"
            >
              {item}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
