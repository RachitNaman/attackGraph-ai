import { Handle, Position } from "@xyflow/react";
import { nodeStyle, T } from "../../../lib/designTokens";

type UserNodeData = {
  label: string;
  sub: string;
  is_admin?: boolean;
};

export function UserNode({ data, selected }: { data: UserNodeData; selected?: boolean }) {
  return (
    <div style={{ ...nodeStyle(T.nodeUser, "#2a4d6a", selected), minWidth: 140 }}>
      <Handle type="target" position={Position.Top} style={{ background: "#5dade2", border: "none", width: 6, height: 6 }} />
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <div style={{ width: 7, height: 7, borderRadius: "50%", background: data.is_admin ? "#e74c3c" : "#5dade2", flexShrink: 0 }} />
        <div>
          <div style={{ fontSize: 12, fontWeight: 600, color: T.text0, fontFamily: "'IBM Plex Mono', monospace" }}>{data.label}</div>
          <div style={{ fontSize: 10, color: T.text1, marginTop: 2 }}>{data.sub}</div>
          {data.is_admin && (
            <div style={{ marginTop: 4, display: "inline-flex", alignItems: "center", gap: 4, background: "#2a080808", border: "1px solid #8b2020", borderRadius: 4, padding: "1px 6px" }}>
              <span style={{ fontSize: 9, color: "#e05555", fontWeight: 700 }}>ROOT</span>
            </div>
          )}
        </div>
      </div>
      <Handle type="source" position={Position.Bottom} style={{ background: "#5dade2", border: "none", width: 6, height: 6 }} />
    </div>
  );
}
