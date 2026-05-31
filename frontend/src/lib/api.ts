import axios from "axios";

export const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000",
});

export const endpoints = {
  analyze: "/api/v1/analysis/analyze",
  graphSummary: "/api/v1/graph/summary",
  health: "/api/v1/health",
};
