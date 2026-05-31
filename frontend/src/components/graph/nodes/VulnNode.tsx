import { Handle, Position } from "@xyflow/react";
import { nodeStyle, T } from "../../../lib/designTokens";

type VulnNodeData = {
  label: string;
  sub: string;
  cvss: number;
  exploitable?: boolean;
};

export function VulnNode({ data, selected }: { data: VulnNodeData; selected?: boolean }) {
  const isCritical = data.cvss >= 9.0;
  const isHigh = data.cvss >= 7.0;
  const color = isCritical ? "#e05555" : isHigh ? "#d4891a" : "#c4a820";
  const bg = isCritical ? "#200a0a" : isHigh ? "#201008" : "#18180a";
  const border = isCritical ? "#6a2020" : isHigh ? "#6a4010" : "#5a5010";

  return (
    <div style={{ ...nodeStyle(bg, border, selected), minWidth: 140 }}>
      <Handle type="target" position={Position.Top} style={{ background: color, border: "none", width: 6, height: 6 }} />
      <div style={{ display: "flex", alignItems: "flex-start", gap: 7 }}>
        <div style={{ width: 6, height: 6, borderRadius: 1, background: color, flexShrink: 0, marginTop: 3 }} />
        <div>
          <div style={{ fontSize: 11, fontWeight: 700, color, fontFamily: "'IBM Plex Mono', monospace" }}>{data.label}</div>
          <div style={{ fontSize: 10, color: T.text1, marginTop: 1 }}>{data.sub}</div>
          <div style={{ marginTop: 4, display: "flex", gap: 4 }}>
            <span style={{ fontSize: 9, fontWeight: 700, color, background: `${color}18`, border: `1px solid ${color}40`, borderRadius: 3, padding: "1px 5px" }}>
              CVSS {data.cvss.toFixed(1)}
            </span>
            {data.exploitable && (
              <span style={{ fontSize: 9, fontWeight: 600, color: "#e05555", background: "#2a080808", border: "1px solid #6a202080", borderRadius: 3, padding: "1px 5px" }}>
                EXPLOIT
              </span>
            )}
          </div>
        </div>
      </div>
      <Handle type="source" position={Position.Bottom} style={{ background: color, border: "none", width: 6, height: 6 }} />
    </div>
  );
}
