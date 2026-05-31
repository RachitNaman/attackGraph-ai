export const T = {
  bg0: "#0a0b0d",
  bg1: "#0f1117",
  bg2: "#141720",
  bg3: "#1c2030",
  bg4: "#242840",
  border: "#1e2235",
  border2: "#2a2f4a",
  text0: "#e8eaf2",
  text1: "#9299b8",
  text2: "#5a6080",
  text3: "#3a3f5c",
  accent: "#4a7fa5",
  accent2: "#5c9cc5",
  critical: "#c0392b",
  high: "#c67c1a",
  medium: "#7a6b1a",
  low: "#2e7a4a",
  nodeHost: "#1e3a5f",
  nodeDB: "#3d1e5f",
  nodeSvc: "#1e4d3a",
  nodeVuln: "#5f2a1e",
  nodeUser: "#1e3d50",
} as const;

export const RISK_CONFIG = {
  CRITICAL: { bg: "#2a0f0f", border: "#8b2020", text: "#e05555", dot: "#e05555" },
  HIGH: { bg: "#2a1a0a", border: "#8b5a15", text: "#d4891a", dot: "#d4891a" },
  MEDIUM: { bg: "#1e1e0a", border: "#6b5c10", text: "#c4a820", dot: "#c4a820" },
  LOW: { bg: "#0a1e12", border: "#1e6b36", text: "#3db864", dot: "#3db864" },
} as const;

export type RiskLevel = keyof typeof RISK_CONFIG;

export function nodeStyle(bg: string, border: string, active?: boolean) {
  return {
    background: active ? bg.replace("1e", "2a").replace("3d", "52") : bg,
    border: `1px solid ${active ? border.replace("1e", "4a").replace("3d", "6a") : border}`,
    borderRadius: 8,
    padding: "10px 14px",
    minWidth: 160,
    cursor: "pointer",
    transition: "all 0.15s ease",
    boxShadow: active ? `0 0 0 1px ${border}40` : "none",
  };
}
