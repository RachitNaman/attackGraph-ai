import { T } from "../../lib/designTokens";
import { RiskBadge } from "../analysis/RiskBadge";

export function RiskOverview({
  metrics,
}: {
  metrics: Array<{ label: string; value: string; sub?: string; accent?: string }>;
}) {
  return (
    <div style={{ padding: "12px 16px", borderBottom: `1px solid ${T.border}`, display: "flex", gap: 10, flexShrink: 0 }}>
      {metrics.map((metric) => (
        <div key={metric.label} style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 8, padding: "14px 16px", flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 10, color: T.text2, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600, marginBottom: 6 }}>
            {metric.label}
          </div>
          <div style={{ fontSize: 24, fontWeight: 700, color: metric.accent || T.text0, fontFamily: "'IBM Plex Mono', monospace", lineHeight: 1 }}>
            {metric.value}
          </div>
          {metric.sub && <div style={{ fontSize: 10, color: T.text2, marginTop: 5 }}>{metric.sub}</div>}
        </div>
      ))}
      <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 8, padding: "14px 16px", flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 10, color: T.text2, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600, marginBottom: 6 }}>
          Risk Level
        </div>
        <RiskBadge level="HIGH" size="lg" />
        <div style={{ fontSize: 10, color: T.text2, marginTop: 5 }}>Immediate action</div>
      </div>
    </div>
  );
}
