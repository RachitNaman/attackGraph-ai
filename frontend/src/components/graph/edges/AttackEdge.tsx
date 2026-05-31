import { BaseEdge, EdgeLabelRenderer, type EdgeProps, getBezierPath } from "@xyflow/react";
import { T } from "../../../lib/designTokens";

export function AttackEdge(props: EdgeProps) {
  const { id, sourceX, sourceY, targetX, targetY, data, selected } = props;
  const edgeData = data as { label?: string } | undefined;
  const [edgePath, labelX, labelY] = getBezierPath({ sourceX, sourceY, targetX, targetY });
  const isHighRisk = ["HAS_VULN", "ESCALATES_TO"].includes(edgeData?.label || "");
  const stroke = isHighRisk ? (selected ? "#e05555" : "#5a2020") : selected ? T.accent2 : T.border2;

  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        markerEnd={props.markerEnd}
        style={{
          stroke,
          strokeWidth: selected ? 1.5 : 0.8,
          strokeDasharray: isHighRisk ? "none" : "4 3",
          transition: "stroke 0.15s, stroke-width 0.15s",
        }}
      />
      {edgeData?.label && (
        <EdgeLabelRenderer>
          <div
            style={{
              position: "absolute",
              transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
              fontSize: 9,
              fontFamily: "'IBM Plex Mono', monospace",
              color: T.text2,
              pointerEvents: "all",
              background: T.bg0,
              border: `1px solid ${T.border}`,
              borderRadius: 3,
              padding: "1px 4px",
            }}
          >
            {edgeData.label}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}
