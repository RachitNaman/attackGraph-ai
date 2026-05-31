export interface GraphNode {
  id: string;
  label: string;
  type: "Host" | "Service" | "Database" | "Vulnerability" | "User";
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
}
