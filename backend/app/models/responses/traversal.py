"""
models/responses/traversal.py
==============================
Response models specifically for graph traversal API endpoints.

These EXTEND (not replace) the existing models in graph.py.
Import both files when you need the full set of models.

Why separate file?
- graph.py has foundational models (HostResponse, VulnerabilityResponse, etc.)
- traversal.py has complex composite models for traversal results
- Keeps each file a manageable size
- You can find traversal-specific shapes instantly
"""

from pydantic import BaseModel, Field
from typing import Any


# ===========================================================================
# SHARED BUILDING BLOCKS
# ===========================================================================

class PathNodeDetail(BaseModel):
    """
    A single node inside any traversal result.
    Richer than the basic PathNode in graph.py —
    includes traversal-specific fields like hop distance.
    """
    id: str
    label: str                      # Host, Service, Vulnerability, User, Database
    name: str                       # Human readable
    ip_address: str = ""
    subnet: str = ""
    cvss_score: float | None = None
    is_critical: bool = False
    contains_pii: bool = False


class PathEdgeDetail(BaseModel):
    """A single relationship (edge) in a traversal result."""
    type: str                       # CONNECTS_TO, RUNS, HAS_VULNERABILITY, etc.
    port: int | None = None
    protocol: str = ""


# ===========================================================================
# REACHABLE SYSTEMS RESPONSE
# ===========================================================================

class ReachableNode(BaseModel):
    """One node reachable from a compromised host."""
    id: str
    label: str
    name: str
    ip_address: str = ""
    is_critical: bool = False
    cvss_score: float | None = None
    min_hops: int                   # Shortest path distance from source


class ReachableSystemsResponse(BaseModel):
    """
    Full response for the reachable systems query.
    Answers: "If host X is compromised, what can the attacker reach?"
    """
    source_host_id: str
    source_hostname: str = ""
    total_reachable: int
    max_hops_used: int
    reachable_nodes: list[ReachableNode]

    # Breakdown by node type for quick summary
    hosts_reachable: int = 0
    databases_reachable: int = 0
    services_reachable: int = 0
    users_reachable: int = 0
    critical_assets_reachable: int = 0

    def compute_summary(self) -> "ReachableSystemsResponse":
        """Calculate summary counts from reachable_nodes list."""
        self.hosts_reachable = sum(1 for n in self.reachable_nodes if n.label == "Host")
        self.databases_reachable = sum(1 for n in self.reachable_nodes if n.label == "Database")
        self.services_reachable = sum(1 for n in self.reachable_nodes if n.label == "Service")
        self.users_reachable = sum(1 for n in self.reachable_nodes if n.label == "User")
        self.critical_assets_reachable = sum(1 for n in self.reachable_nodes if n.is_critical)
        return self


# ===========================================================================
# SHORTEST PATH RESPONSE
# ===========================================================================

class ShortestPathResponse(BaseModel):
    """
    Result of a shortest path query between two nodes.
    Answers: "What is the quickest route an attacker can take?"
    """
    source_id: str
    target_id: str
    found: bool                         # False if no path exists
    hop_count: int = 0
    nodes: list[dict] = Field(default_factory=list)
    relationships: list[dict] = Field(default_factory=list)

    # Derived risk fields
    vulnerabilities_on_path: list[str] = Field(default_factory=list)  # CVE IDs
    max_cvss_on_path: float = 0.0
    has_public_exploit_on_path: bool = False


class AllShortestPathsResponse(BaseModel):
    """
    All paths that tie for shortest length between two nodes.
    Critical insight: if 3 paths all take 4 hops,
    patching one vulnerability doesn't block the others.
    """
    source_id: str
    target_id: str
    shortest_hop_count: int
    total_shortest_paths: int           # How many paths tie for shortest
    paths: list[ShortestPathResponse]

    @property
    def is_redundantly_exposed(self) -> bool:
        """True if multiple equal-length paths exist — patching one isn't enough."""
        return self.total_shortest_paths > 1


# ===========================================================================
# VULNERABLE HOSTS RESPONSE
# ===========================================================================

class VulnerableHostDetail(BaseModel):
    """
    A host with its vulnerability profile.
    Richer than HostResponse — includes aggregated vulnerability stats.
    """
    host_id: str
    hostname: str
    ip_address: str
    os: str = ""
    subnet: str = ""
    is_internet_facing: bool
    is_critical: bool
    asset_group: str = ""

    # Vulnerability statistics
    total_vulns: int
    max_cvss: float
    exploitable_count: int
    public_exploit_count: int
    risk_score: float

    # Top vulnerabilities list
    vulnerabilities: list[dict] = Field(default_factory=list)

    @property
    def risk_level(self) -> str:
        """Human readable risk level derived from risk score."""
        if self.risk_score >= 15:
            return "CRITICAL"
        elif self.risk_score >= 10:
            return "HIGH"
        elif self.risk_score >= 5:
            return "MEDIUM"
        return "LOW"


class VulnerableHostsResponse(BaseModel):
    """Paginated list of vulnerable hosts ranked by risk."""
    total: int
    page: int
    page_size: int
    min_cvss_filter: float
    hosts: list[VulnerableHostDetail]


# ===========================================================================
# BLAST RADIUS RESPONSE
# ===========================================================================

class BlastRadiusNodeType(BaseModel):
    """Count of affected nodes by type."""
    node_type: str
    affected_count: int
    critical_count: int
    pii_count: int
    sample_nodes: list[dict] = Field(default_factory=list)


class BlastRadiusTimelineEntry(BaseModel):
    """How many nodes reachable at each hop distance."""
    hops_from_source: int
    nodes_reachable: int
    node_types_at_distance: list[str]
    examples: list[str]


class BlastRadiusResponse(BaseModel):
    """
    Full blast radius analysis for a compromised host.
    Answers: "If this host is compromised, what is the damage?"
    """
    compromised_host_id: str
    compromised_hostname: str = ""
    max_hops_analyzed: int

    # Summary numbers
    total_affected_nodes: int
    total_critical_assets: int
    total_pii_systems: int

    # Overall severity
    blast_severity: str = "LOW"     # LOW, MEDIUM, HIGH, CRITICAL

    # Detailed breakdowns
    by_node_type: list[BlastRadiusNodeType]
    timeline: list[BlastRadiusTimelineEntry]     # expansion per hop
    critical_assets_exposed: list[dict]          # the crown jewels

    def compute_severity(self) -> "BlastRadiusResponse":
        """Derive blast severity from the numbers."""
        if self.total_critical_assets >= 3 or self.total_pii_systems >= 2:
            self.blast_severity = "CRITICAL"
        elif self.total_critical_assets >= 1 or self.total_affected_nodes >= 20:
            self.blast_severity = "HIGH"
        elif self.total_affected_nodes >= 10:
            self.blast_severity = "MEDIUM"
        else:
            self.blast_severity = "LOW"
        return self


# ===========================================================================
# PRIVILEGE ESCALATION RESPONSE
# ===========================================================================

class EscalationStep(BaseModel):
    """One step in a privilege escalation chain."""
    id: str
    label: str
    name: str
    cvss_score: float | None = None
    exploit_maturity: str = ""


class PrivilegeEscalationChain(BaseModel):
    """
    A complete privilege escalation chain from entry to admin.
    Answers: "How does an attacker become admin/root?"
    """
    entry_host_id: str
    entry_hostname: str
    entry_ip: str
    entry_internet_facing: bool = False

    # The full chain of steps
    chain_nodes: list[dict]
    chain_relationships: list[str]
    chain_length: int

    # Target privilege gained
    target_username: str
    is_admin: bool

    # Risk metrics
    exploited_vulnerabilities: list[dict]
    total_cvss: float

    @property
    def risk_level(self) -> str:
        if self.total_cvss >= 18:
            return "CRITICAL"
        elif self.total_cvss >= 12:
            return "HIGH"
        elif self.total_cvss >= 6:
            return "MEDIUM"
        return "LOW"

    @property
    def is_fully_automated(self) -> bool:
        """True if all exploits are weaponized — attacker needs no manual steps."""
        return all(
            v.get("exploit_maturity") == "weaponized"
            for v in self.exploited_vulnerabilities
        )


class PrivilegeEscalationResponse(BaseModel):
    """Full privilege escalation analysis result."""
    total_chains_found: int
    chains: list[PrivilegeEscalationChain]

    # Summary stats
    hosts_with_escalation_paths: int = 0
    fully_automated_chains: int = 0     # chains requiring no manual attacker steps

    def compute_summary(self) -> "PrivilegeEscalationResponse":
        unique_hosts = {c.entry_host_id for c in self.chains}
        self.hosts_with_escalation_paths = len(unique_hosts)
        self.fully_automated_chains = sum(1 for c in self.chains if c.is_fully_automated)
        return self


class EscalationToRootEntry(BaseModel):
    """A single internet-entry → root escalation path."""
    entry_id: str
    entry_hostname: str
    entry_ip: str
    escalation_cve: str
    cvss_score: float
    exploit_maturity: str
    has_public_exploit: bool
    admin_username: str
    admin_id: str
    full_path: list[dict]
    hops: int


class EscalationToRootResponse(BaseModel):
    """
    All paths from internet entry directly to root/admin.
    These are the MOST CRITICAL findings — immediate action required.
    """
    total_found: int
    entries: list[EscalationToRootEntry]
    immediate_action_required: bool = False

    def compute_flags(self) -> "EscalationToRootResponse":
        self.immediate_action_required = any(
            e.has_public_exploit and e.cvss_score >= 7.0
            for e in self.entries
        )
        return self
