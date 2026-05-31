"use client";

import { Background, Controls, MarkerType, ReactFlow, type Edge, type Node, type OnEdgesChange, type OnNodesChange } from "@xyflow/react";
import { T } from "../../lib/designTokens";
import { AttackEdge } from "./edges/AttackEdge";
import { DatabaseNode } from "./nodes/DatabaseNode";
import { HostNode } from "./nodes/HostNode";
import { UserNode } from "./nodes/UserNode";
import { VulnNode } from "./nodes/VulnNode";

const nodeTypes = {
  hostNode: HostNode,
  vulnNode: VulnNode,
  databaseNode: DatabaseNode,
  userNode: UserNode,
};

const edgeTypes = {
  attackEdge: AttackEdge,
};

function GraphLegend() {
  const items = [
    { color: T.accent, label: "Host" },
    { color: "#9b59b6", label: "Database" },
    { color: "#e05555", label: "Vulnerability" },
    { color: "#5dade2", label: "User / Account" },
  ];

  return (
    <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
      {items.map(({ color, label }) => (
        <div key={label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <div style={{ width: 6, height: 6, borderRadius: "50%", background: color }} />
          <span style={{ fontSize: 10, color: T.text2 }}>{label}</span>
        </div>
      ))}
    </div>
  );
}

export function AttackGraph({
  nodes,
  edges,
  onNodesChange,
  onEdgesChange,
  onAnalyze,
}: {
  nodes: Node[];
  edges: Edge[];
  onNodesChange: OnNodesChange;
  onEdgesChange: OnEdgesChange;
  onAnalyze: () => void;
}) {
  const styledEdges = edges.map((edge) => ({
    ...edge,
    markerEnd: {
      type: MarkerType.ArrowClosed,
      color: ["HAS_VULN", "ESCALATES_TO"].includes(String(edge.data?.label)) ? "#5a2020" : T.border2,
      width: 16,
      height: 16,
    },
  }));

  return (
    <div style={{ flex: 1, position: "relative", overflow: "hidden" }}>
      <div style={{ position: "absolute", top: 12, left: 12, zIndex: 10, display: "flex", alignItems: "center", gap: 8 }}>
        <span style={{ fontSize: 10, color: T.text2, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600 }}>ATTACK GRAPH</span>
        <GraphLegend />
      </div>
      <button
        onClick={onAnalyze}
        style={{ position: "absolute", bottom: 16, left: "50%", transform: "translateX(-50%)", zIndex: 10, background: T.accent, border: "none", borderRadius: 6, padding: "8px 20px", color: "#fff", fontSize: 12, fontWeight: 600, cursor: "pointer" }}
        type="button"
      >
        Analyze with AI
      </button>
      <ReactFlow
        nodes={nodes}
        edges={styledEdges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        style={{ background: T.bg0 }}
        proOptions={{ hideAttribution: true }}
      >
        <Background color={T.border} gap={28} size={0.5} />
        <Controls style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 8 }} />
      </ReactFlow>
    </div>
  );
}
