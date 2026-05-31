import { T } from "../../lib/designTokens";
import { RiskBadge } from "./RiskBadge";

type AnalysisResult = {
  risk_level: string;
  duration_ms: number;
  total_paths_found: number;
  executive_summary: string;
  path_summaries?: string[];
  recommendations?: string[];
  highest_cvss: number;
  has_public_exploit: boolean;
  immediate_action_required: boolean;
};

export function ResultsPanel({
  result,
  loading,
}: {
  result: AnalysisResult | null;
  loading: boolean;
}) {
  if (loading) {
    return (
      <div style={{ flex: 1, overflow: "auto", padding: "16px" }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {["Parsing query intent...", "Traversing attack graph...", "Enriching CVE context...", "Scoring paths..."].map((step, index) => (
            <div key={step} style={{ display: "flex", alignItems: "center", gap: 8, opacity: 1 - index * 0.2 }}>
              <div style={{ width: 6, height: 6, borderRadius: "50%", background: index === 0 ? T.accent2 : T.border2, animation: index === 0 ? "pulse 1s infinite" : "none" }} />
              <span style={{ fontSize: 11, color: index === 0 ? T.text1 : T.text2 }}>{step}</span>
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (!result) {
    return (
      <div style={{ flex: 1, overflow: "auto", padding: "16px" }}>
        <div style={{ textAlign: "center", padding: "40px 0" }}>
          <div style={{ fontSize: 28, marginBottom: 12, opacity: 0.3 }}>AI</div>
          <div style={{ fontSize: 12, color: T.text2 }}>Run a query to see AI-powered attack path analysis</div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ flex: 1, overflow: "auto", padding: "16px" }}>
      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <RiskBadge level={result.risk_level} size="lg" />
          <div style={{ fontSize: 10, color: T.text2 }}>{result.duration_ms}ms - {result.total_paths_found} paths</div>
        </div>

        <div style={{ background: T.bg3, border: `1px solid ${T.border}`, borderRadius: 6, padding: "12px 14px" }}>
          <div style={{ fontSize: 9, color: T.text2, textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 8, fontWeight: 600 }}>
            EXECUTIVE SUMMARY
          </div>
          <p style={{ fontSize: 12, color: T.text1, lineHeight: 1.6, margin: 0 }}>{result.executive_summary}</p>
        </div>

        {!!result.path_summaries?.length && (
          <div>
            <div style={{ fontSize: 9, color: T.text2, textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 8, fontWeight: 600 }}>
              ATTACK PATHS
            </div>
            {result.path_summaries.map((path, index) => (
              <div key={path} style={{ background: T.bg3, border: `1px solid ${T.border}`, borderRadius: 5, padding: "8px 12px", marginBottom: 5, fontSize: 11, color: T.text1, fontFamily: "'IBM Plex Mono', monospace", lineHeight: 1.5 }}>
                <span style={{ color: T.text2, marginRight: 8 }}>#{index + 1}</span>{path}
              </div>
            ))}
          </div>
        )}

        {!!result.recommendations?.length && (
          <div>
            <div style={{ fontSize: 9, color: T.text2, textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 8, fontWeight: 600 }}>
              REMEDIATION
            </div>
            {result.recommendations.map((rec, index) => (
              <div key={rec} style={{ display: "flex", gap: 10, marginBottom: 8, padding: "8px 12px", background: T.bg3, border: `1px solid ${T.border}`, borderRadius: 5 }}>
                <div style={{ width: 18, height: 18, borderRadius: 4, background: index === 0 ? "#2a1a0a" : T.bg4, border: `1px solid ${index === 0 ? "#8b5a15" : T.border}`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                  <span style={{ fontSize: 9, fontWeight: 700, color: index === 0 ? "#d4891a" : T.text2 }}>{index + 1}</span>
                </div>
                <p style={{ fontSize: 11, color: T.text1, margin: 0, lineHeight: 1.5 }}>{rec}</p>
              </div>
            ))}
          </div>
        )}

        {result.highest_cvss > 0 && (
          <div style={{ display: "flex", gap: 6 }}>
            <SummaryTile label="MAX CVSS" value={result.highest_cvss.toFixed(1)} danger={result.highest_cvss >= 9} />
            <SummaryTile label="PUBLIC EXPLOIT" value={result.has_public_exploit ? "YES" : "NO"} danger={result.has_public_exploit} />
            <SummaryTile label="IMMED. ACTION" value={result.immediate_action_required ? "YES" : "NO"} danger={result.immediate_action_required} />
          </div>
        )}
      </div>
    </div>
  );
}

function SummaryTile({ label, value, danger }: { label: string; value: string; danger: boolean }) {
  return (
    <div style={{ flex: 1, background: T.bg3, border: `1px solid ${T.border}`, borderRadius: 5, padding: "8px 12px" }}>
      <div style={{ fontSize: 9, color: T.text2, marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 18, fontWeight: 700, color: danger ? "#e05555" : "#3db864", fontFamily: "'IBM Plex Mono', monospace" }}>{value}</div>
    </div>
  );
}
