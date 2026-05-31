import { Handle, Position } from "@xyflow/react";
import { nodeStyle, T } from "../../../lib/designTokens";

type HostNodeData = {
  label: string;
  sub: string;
  type?: string;
  ip?: string;
  critical?: boolean;
  vuln_count?: number;
};

export function HostNode({ data, selected }: { data: HostNodeData; selected?: boolean }) {
  const isInternet = data.type === "internet";
  const bg = isInternet ? T.bg3 : data.critical ? "#1a1020" : T.nodeHost;
  const border = isInternet ? T.border2 : data.critical ? "#5a2a6a" : "#2a4a6a";

  return (
    <div style={nodeStyle(bg, border, selected)}>
      <Handle type="target" position={Position.Top} style={{ background: T.accent, border: "none", width: 6, height: 6 }} />
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <div style={{ width: 7, height: 7, borderRadius: "50%", background: data.critical ? "#9b59b6" : isInternet ? T.text2 : T.accent, flexShrink: 0 }} />
        <div>
          <div style={{ fontSize: 12, fontWeight: 600, color: T.text0, fontFamily: "'IBM Plex Mono', monospace", letterSpacing: "0.02em" }}>
            {data.label}
          </div>
          <div style={{ fontSize: 10, color: T.text1, marginTop: 2 }}>{data.sub}</div>
          {data.ip && <div style={{ fontSize: 10, color: T.text2, fontFamily: "'IBM Plex Mono', monospace", marginTop: 1 }}>{data.ip}</div>}
          {(data.vuln_count || 0) > 0 && (
            <div style={{ marginTop: 5, display: "inline-flex", alignItems: "center", gap: 4, background: "#2a1a0a", border: "1px solid #5a3a10", borderRadius: 4, padding: "1px 6px" }}>
              <div style={{ width: 4, height: 4, borderRadius: "50%", background: "#d4891a" }} />
              <span style={{ fontSize: 9, color: "#d4891a", fontWeight: 600 }}>
                {data.vuln_count} VULN{(data.vuln_count || 0) > 1 ? "S" : ""}
              </span>
            </div>
          )}
        </div>
      </div>
      <Handle type="source" position={Position.Bottom} style={{ background: T.accent, border: "none", width: 6, height: 6 }} />
    </div>
  );
}
