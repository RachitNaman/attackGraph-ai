"""
models/responses/graph.py
==========================
Pydantic response models for graph-related API responses.

These models serve three purposes:
1. Validate outgoing data (catch bugs before they reach the client)
2. Serialize Python objects to JSON automatically
3. Generate API documentation (FastAPI reads these for /docs)

from_neo4j() classmethods:
    Neo4j returns records as dicts with nested objects.
    These classmethods handle the translation from raw Neo4j
    data to clean Pydantic models, keeping that logic
    in one place rather than scattered across services.
"""

from pydantic import BaseModel, Field
from typing import Any
from datetime import datetime


# ===========================================================================
# NODE RESPONSE MODELS
# ===========================================================================

class HostResponse(BaseModel):
    id: str
    ip_address: str
    hostname: str = ""
    os: str = ""
    os_version: str = ""
    subnet: str = ""
    is_internet_facing: bool = False
    is_critical: bool = False
    asset_group: str = "Internal"
    vuln_count: int = 0
    services: list[dict] = Field(default_factory=list)
    vulnerabilities: list[dict] = Field(default_factory=list)

    @classmethod
    def from_neo4j(
        cls,
        node: dict | Any,
        services: list = None,
        vulnerabilities: list = None,
        vuln_count: int = 0,
    ) -> "HostResponse":
        """
        Convert a raw Neo4j node to a HostResponse.
        Neo4j nodes behave like dicts — access properties with node["property"].
        """
        # Neo4j node objects support dict-like access
        props = dict(node) if hasattr(node, "__iter__") else node

        return cls(
            id=props.get("id", ""),
            ip_address=props.get("ip_address", ""),
            hostname=props.get("hostname", ""),
            os=props.get("os", ""),
            os_version=props.get("os_version", ""),
            subnet=props.get("subnet", ""),
            is_internet_facing=props.get("is_internet_facing", False),
            is_critical=props.get("is_critical", False),
            asset_group=props.get("asset_group", "Internal"),
            vuln_count=vuln_count,
            services=[dict(s) for s in (services or []) if s],
            vulnerabilities=[dict(v) for v in (vulnerabilities or []) if v],
        )


class ServiceResponse(BaseModel):
    id: str
    host_id: str
    name: str = ""
    port: int
    protocol: str = "tcp"
    version: str = ""
    banner: str = ""
    is_encrypted: bool = False


class VulnerabilityResponse(BaseModel):
    id: str
    cve_id: str
    description: str = ""
    cvss_score: float = 0.0
    severity: str = "UNKNOWN"
    cwe_id: str = ""
    is_exploitable: bool = False
    has_public_exploit: bool = False
    exploit_maturity: str = "unproven"
    patch_available: bool = False
    affected_hosts: int = 0


class UserResponse(BaseModel):
    id: str
    username: str
    display_name: str = ""
    is_admin: bool = False
    is_service_account: bool = False
    department: str = ""


class DatabaseResponse(BaseModel):
    id: str
    name: str
    type: str  # postgresql, mysql, mongodb
    version: str = ""
    port: int = 5432
    contains_pii: bool = False
    contains_secrets: bool = False
    is_encrypted: bool = False


# ===========================================================================
# ATTACK PATH RESPONSE MODELS
# ===========================================================================

class PathNode(BaseModel):
    """A single node in an attack path."""
    id: str
    label: str      # Host, Service, Vulnerability, etc.
    name: str       # Human-readable name
    ip_address: str = ""
    cvss_score: float | None = None


class AttackPathResponse(BaseModel):
    """A single attack path from source to target."""
    nodes: list[dict]               # Sequence of nodes
    relationship_types: list[str]   # Sequence of relationship types between nodes
    hop_count: int                  # Number of hops (edges) in the path
    risk_score: float = 0.0        # Composite risk score (calculated by scoring service)
    cve_ids: list[str] = Field(default_factory=list)  # CVEs on this path
    has_public_exploit: bool = False


class AttackAnalysisResponse(BaseModel):
    """Full response for an attack path analysis query."""
    query: str
    session_id: str
    paths: list[AttackPathResponse]
    explanation: str                # Gemini-generated narrative
    recommendations: list[str]     # Remediation suggestions
    risk_level: str                 # CRITICAL, HIGH, MEDIUM, LOW
    total_paths_found: int
    analysis_duration_ms: int


# ===========================================================================
# GRAPH SUMMARY MODELS
# ===========================================================================

class GraphSummaryResponse(BaseModel):
    """Overview of the entire graph database contents."""
    node_counts: dict[str, int]         # {"Host": 42, "Service": 128, ...}
    relationship_counts: dict[str, int] # {"RUNS": 128, "HAS_VULNERABILITY": 89, ...}

    @property
    def total_nodes(self) -> int:
        return sum(self.node_counts.values())

    @property
    def total_relationships(self) -> int:
        return sum(self.relationship_counts.values())
