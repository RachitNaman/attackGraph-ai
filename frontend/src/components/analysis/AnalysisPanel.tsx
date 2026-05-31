"use client";

import type { AnalysisResponse } from "../../types/analysis";
import { QueryPanel } from "./QueryPanel";
import { ResultsPanel } from "./ResultsPanel";

export function AnalysisPanel({
  onAnalyze,
  result,
  loading,
}: {
  onAnalyze: (query: string) => void;
  result: AnalysisResponse | null;
  loading: boolean;
}) {
  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", overflow: "hidden" }}>
      <QueryPanel onAnalyze={onAnalyze} loading={loading} />
      <ResultsPanel result={result} loading={loading} />
    </div>
  );
}
