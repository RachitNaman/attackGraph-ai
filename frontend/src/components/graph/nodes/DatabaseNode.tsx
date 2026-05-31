import { Handle, Position } from "@xyflow/react";
import { nodeStyle, T } from "../../../lib/designTokens";

type DatabaseNodeData = {
  label: string;
  sub: string;
};

export function DatabaseNode({ data, selected }: { data: DatabaseNodeData; selected?: boolean }) {
  return (
    <div style={{ ...nodeStyle(T.nodeDB, "#4a2a6a", selected), minWidth: 150 }}>
      <Handle type="target" position={Position.Top} style={{ background: "#9b59b6", border: "none", width: 6, height: 6 }} />
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <div style={{ width: 7, height: 7, borderRadius: 1, background: "#9b59b6", flexShrink: 0 }} />
        <div>
          <div style={{ fontSize: 12, fontWeight: 600, color: "#c39bd3", fontFamily: "'IBM Plex Mono', monospace" }}>{data.label}</div>
          <div style={{ fontSize: 10, color: T.text1, marginTop: 2 }}>{data.sub}</div>
        </div>
      </div>
      <Handle type="source" position={Position.Bottom} style={{ background: "#9b59b6", border: "none", width: 6, height: 6 }} />
    </div>
  );
}
