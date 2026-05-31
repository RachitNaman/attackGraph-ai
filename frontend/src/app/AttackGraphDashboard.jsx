"use client";

import { useCallback, useState } from "react";
import { useEdgesState, useNodesState } from "@xyflow/react";
import { AnalysisPanel } from "../components/analysis/AnalysisPanel";
import { RiskOverview } from "../components/dashboard/RiskOverview";
import { AttackGraph } from "../components/graph/AttackGraph";
import { AppShell } from "../components/layout/AppShell";
import { MOCK_RESULT } from "../lib/mockAnalysis";
import { METRICS, SEED_EDGES, SEED_NODES } from "../lib/seedGraph";
import { T } from "../lib/designTokens";

export default function AttackGraphDashboard() {
  const [activeView, setActiveView] = useState("graph");
  const [nodes, , onNodesChange] = useNodesState(SEED_NODES);
  const [edges, setEdges, onEdgesChange] = useEdgesState(SEED_EDGES);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [analysisLoading, setAnalysisLoading] = useState(false);

  const handleAnalyze = useCallback(
    async (query) => {
      setAnalysisLoading(true);
      setActiveView("analysis");

      try {
        const response = await fetch("http://localhost:8000/api/v1/analysis/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ query, max_hops: 8 }),
        });

        if (response.ok) {
          const data = await response.json();
          setAnalysisResult(data);
          if (data.total_paths_found > 0) {
            setEdges((previous) =>
              previous.map((edge) => ({
                ...edge,
                data: { ...edge.data, animated: ["CONNECTS_TO", "HAS_VULN"].includes(String(edge.data?.label)) },
              })),
            );
          }
        } else {
          setAnalysisResult(MOCK_RESULT);
        }
      } catch {
        setAnalysisResult(MOCK_RESULT);
      } finally {
        setAnalysisLoading(false);
      }
    },
    [setEdges],
  );

  return (
    <AppShell activeView={activeView} setActiveView={setActiveView}>
      <RiskOverview metrics={METRICS} />
      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        {activeView !== "analysis" && (
          <>
            <AttackGraph
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onAnalyze={() => handleAnalyze("How can an attacker reach the database?")}
            />
            <div style={{ width: 320, borderLeft: `1px solid ${T.border}`, background: T.bg1, overflow: "hidden", flexShrink: 0 }}>
              <AnalysisPanel onAnalyze={handleAnalyze} result={analysisResult} loading={analysisLoading} />
            </div>
          </>
        )}

        {activeView === "analysis" && (
          <div style={{ flex: 1, overflow: "hidden", borderLeft: `1px solid ${T.border}` }}>
            <AnalysisPanel onAnalyze={handleAnalyze} result={analysisResult} loading={analysisLoading} />
          </div>
        )}
      </div>
    </AppShell>
  );
}
