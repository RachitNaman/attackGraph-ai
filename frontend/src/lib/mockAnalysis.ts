export const MOCK_RESULT = {
  session_id: "demo",
  query: "How can an attacker reach the database?",
  risk_level: "HIGH",
  executive_summary:
    "Attackers can reach the production database via web-server-01 by exploiting CVE-2021-44228 (Log4Shell) for initial access, pivoting to app-server-01, then escalating privileges using CVE-2021-4034 (PwnKit) to gain root access before connecting to production-db.",
  explanation: "Full technical narrative available when connected to backend.",
  path_summaries: [
    "web-server-01 -> app-server-01 -> production-db via CVE-2021-4034 (PwnKit)",
    "web-server-01 -> app-server-01 -> db-server-01 -> production-db",
  ],
  recommendations: [
    "[P1] Apply CVE-2021-4034 patch on app-server-01 immediately - eliminates privilege escalation path (Effort: LOW)",
    "[P2] Implement strict network segmentation between app-server-01 and database tier (Effort: MEDIUM)",
    "[P3] Upgrade Log4j2 on web-server-01 to 2.17.1+ to eliminate initial access vector (Effort: LOW)",
    "[P4] Deploy host-based intrusion detection on db-server-01 and app-server-01 (Effort: MEDIUM)",
  ],
  total_paths_found: 2,
  highest_cvss: 10.0,
  has_public_exploit: true,
  immediate_action_required: true,
  duration_ms: 27276,
  error: null,
};
