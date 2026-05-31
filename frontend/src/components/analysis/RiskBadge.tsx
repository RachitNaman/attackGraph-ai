import { RISK_CONFIG, type RiskLevel } from "../../lib/designTokens";

export function RiskBadge({ level, size = "sm" }: { level: string; size?: "sm" | "lg" }) {
  const cfg = RISK_CONFIG[(level as RiskLevel) || "LOW"] || RISK_CONFIG.LOW;
  const padding = size === "lg" ? "5px 12px" : "2px 8px";
  const fontSize = size === "lg" ? 12 : 10;

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 5,
        background: cfg.bg,
        border: `1px solid ${cfg.border}`,
        borderRadius: 4,
        padding,
        fontSize,
        fontWeight: 700,
        color: cfg.text,
        fontFamily: "'IBM Plex Mono', monospace",
        letterSpacing: "0.08em",
      }}
    >
      <span style={{ width: 5, height: 5, borderRadius: "50%", background: cfg.dot, flexShrink: 0 }} />
      {level}
    </span>
  );
}
