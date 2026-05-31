export type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export interface AnalysisResponse {
  session_id: string;
  query: string;
  risk_level: RiskLevel;
  executive_summary: string;
  explanation: string;
  path_summaries: string[];
  recommendations: string[];
  total_paths_found: number;
  highest_cvss: number;
  has_public_exploit: boolean;
  immediate_action_required: boolean;
  duration_ms: number;
  error?: string | null;
}
