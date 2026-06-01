import axios from "axios";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export const api = axios.create({
  baseURL: API_BASE,
  headers: { "Content-Type": "application/json" },
  timeout: 60000,   // 60s — AI analysis takes time
});

export const endpoints = {
  health:       "/api/v1/health",
  analyze:      "/api/v1/analysis/analyze",
  graphSummary: "/api/v1/graph/summary",
  hosts:        "/api/v1/graph/hosts",
  attackPaths:  "/api/v1/traversal/escalation/to-root",
  searchCVEs:   "/api/v1/rag/search/cves",
};