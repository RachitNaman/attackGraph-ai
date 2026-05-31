export const SEED_NODES = [
  { id: "internet", type: "hostNode", position: { x: 340, y: 20 }, data: { label: "Internet", sub: "External attacker", type: "internet", ip: "0.0.0.0/0", critical: false, vuln_count: 0 } },
  { id: "web-server", type: "hostNode", position: { x: 340, y: 140 }, data: { label: "web-server-01", sub: "DMZ - nginx 1.18", type: "host", ip: "203.0.113.10", critical: false, vuln_count: 2 } },
  { id: "cve-log4shell", type: "vulnNode", position: { x: 100, y: 260 }, data: { label: "CVE-2021-44228", sub: "Log4Shell - RCE", cvss: 10.0, exploitable: true } },
  { id: "cve-openssh", type: "vulnNode", position: { x: 580, y: 260 }, data: { label: "CVE-2023-38408", sub: "OpenSSH - RCE", cvss: 9.8, exploitable: true } },
  { id: "app-server", type: "hostNode", position: { x: 340, y: 360 }, data: { label: "app-server-01", sub: "Internal - Tomcat", type: "host", ip: "10.0.1.20", critical: false, vuln_count: 1 } },
  { id: "cve-pwnkit", type: "vulnNode", position: { x: 580, y: 460 }, data: { label: "CVE-2021-4034", sub: "PwnKit - Priv Esc", cvss: 7.8, exploitable: true } },
  { id: "db-server", type: "hostNode", position: { x: 340, y: 560 }, data: { label: "db-server-01", sub: "Internal - Critical", type: "host", ip: "10.0.2.50", critical: true, vuln_count: 1 } },
  { id: "postgres", type: "databaseNode", position: { x: 100, y: 660 }, data: { label: "production-db", sub: "PostgreSQL - PII", type: "postgresql" } },
  { id: "root-user", type: "userNode", position: { x: 580, y: 660 }, data: { label: "root", sub: "Admin account", is_admin: true } },
];

export const SEED_EDGES = [
  { id: "e1", source: "internet", target: "web-server", type: "attackEdge", data: { label: "CONNECTS_TO", animated: false } },
  { id: "e2", source: "web-server", target: "cve-log4shell", type: "attackEdge", data: { label: "HAS_VULN", animated: false } },
  { id: "e3", source: "web-server", target: "cve-openssh", type: "attackEdge", data: { label: "HAS_VULN", animated: false } },
  { id: "e4", source: "web-server", target: "app-server", type: "attackEdge", data: { label: "CONNECTS_TO", animated: false } },
  { id: "e5", source: "app-server", target: "cve-pwnkit", type: "attackEdge", data: { label: "HAS_VULN", animated: false } },
  { id: "e6", source: "app-server", target: "db-server", type: "attackEdge", data: { label: "CONNECTS_TO", animated: false } },
  { id: "e7", source: "db-server", target: "postgres", type: "attackEdge", data: { label: "RUNS", animated: false } },
  { id: "e8", source: "cve-pwnkit", target: "root-user", type: "attackEdge", data: { label: "ESCALATES_TO", animated: false } },
  { id: "e9", source: "root-user", target: "postgres", type: "attackEdge", data: { label: "CAN_ACCESS", animated: false } },
];

export const METRICS = [
  { label: "Total Hosts", value: "4", sub: "1 internet-facing" },
  { label: "Vulnerabilities", value: "4", sub: "3 exploitable", accent: "#d4891a" },
  { label: "Attack Paths", value: "2", sub: "to database", accent: "#e05555" },
  { label: "Highest CVSS", value: "10.0", sub: "CVE-2021-44228", accent: "#e05555" },
];
