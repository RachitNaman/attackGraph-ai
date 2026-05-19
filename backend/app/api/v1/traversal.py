"""
api/v1/traversal.py
====================
FastAPI route handlers for all graph traversal endpoints.

ROUTE ORGANIZATION:
/traversal/reachable/          → reachable systems analysis
/traversal/shortest-path/      → shortest path between nodes
/traversal/vulnerable-hosts/   → vulnerable host discovery
/traversal/blast-radius/       → blast radius analysis
/traversal/escalation/         → privilege escalation chains

Each handler does exactly three things:
1. Validate and extract query parameters
2. Call the traversal service
3. Return the response

Zero business logic. Zero Cypher. Zero database calls.
"""

from fastapi import APIRouter, Depends, Query, Path
from app.services.traversal_service import TraversalService, traversal_service
from app.models.responses.traversal import (
    ReachableSystemsResponse,
    AllShortestPathsResponse,
    ShortestPathResponse,
    VulnerableHostsResponse,
    BlastRadiusResponse,
    PrivilegeEscalationResponse,
    EscalationToRootResponse,
)

router = APIRouter()


# ---------------------------------------------------------------------------
# Dependency — provides TraversalService to all route handlers
# ---------------------------------------------------------------------------

def get_traversal_service() -> TraversalService:
    return traversal_service


# ===========================================================================
# REACHABLE SYSTEMS
# ===========================================================================

@router.get(
    "/reachable/{host_id}",
    response_model=ReachableSystemsResponse,
    summary="Find all systems reachable from a host",
    description="""
    Starting from the given host, traverses the attack graph and returns
    every node reachable within max_hops steps.

    **Use this to answer:** "If this host is compromised, what can the attacker touch?"

    Results include:
    - All reachable hosts, services, databases, users
    - Minimum hop distance to each node
    - Summary counts by node type
    - Critical asset count
    """,
)
async def get_reachable_systems(
    host_id: str = Path(..., description="ID of the starting host (e.g. host-192-168-1-10)"),
    max_hops: int = Query(default=6, ge=1, le=10, description="Maximum traversal depth"),
    service: TraversalService = Depends(get_traversal_service),
) -> ReachableSystemsResponse:
    return await service.find_reachable_systems(host_id=host_id, max_hops=max_hops)


@router.get(
    "/reachable/{host_id}/by-type/{node_type}",
    summary="Find reachable nodes of a specific type",
    description="""
    Filter reachable nodes to a specific type.

    **node_type options:** Host, Service, Database, User, Vulnerability

    **Example:** `/reachable/host-10-0-1-20/by-type/Database`
    → Returns all databases reachable from that host
    """,
)
async def get_reachable_by_type(
    host_id: str = Path(..., description="Starting host ID"),
    node_type: str = Path(..., description="Node type: Host, Service, Database, User, Vulnerability"),
    max_hops: int = Query(default=6, ge=1, le=10),
    limit: int = Query(default=50, le=200),
    service: TraversalService = Depends(get_traversal_service),
):
    return await service.find_reachable_by_type(
        host_id=host_id,
        node_type=node_type,
        max_hops=max_hops,
        limit=limit,
    )


@router.get(
    "/reachable/reverse/{target_id}",
    summary="Find all entry points that can reach a target",
    description="""
    REVERSE traversal — finds all internet-facing hosts from which
    the target asset is reachable.

    **Use this to answer:** "How many attack surfaces lead to this database?"

    If 8 internet-facing hosts can reach your database,
    you have 8 entry points to harden, not just 1.
    """,
)
async def get_nodes_reaching_target(
    target_id: str = Path(..., description="Target node ID (e.g. db-postgres-main)"),
    max_hops: int = Query(default=6, ge=1, le=10),
    service: TraversalService = Depends(get_traversal_service),
):
    return await service.find_nodes_that_reach_target(
        target_id=target_id,
        max_hops=max_hops,
    )


# ===========================================================================
# SHORTEST PATH
# ===========================================================================

@router.get(
    "/shortest-path",
    response_model=ShortestPathResponse,
    summary="Find the shortest attack path between two nodes",
    description="""
    Uses BFS (Breadth-First Search) to find the minimum-hop path
    between source and target.

    **Why shortest path matters:**
    Fewer hops = easier for the attacker = higher probability of success.
    Security teams should prioritize breaking the shortest path first.

    Returns `found: false` if no path exists within max_hops.
    """,
)
async def get_shortest_path(
    source_id: str = Query(..., description="Starting node ID (attacker's entry point)"),
    target_id: str = Query(..., description="Target node ID (what attacker wants)"),
    max_hops: int = Query(default=8, ge=1, le=15),
    service: TraversalService = Depends(get_traversal_service),
) -> ShortestPathResponse:
    return await service.find_shortest_path(
        source_id=source_id,
        target_id=target_id,
        max_hops=max_hops,
    )


@router.get(
    "/shortest-path/all",
    response_model=AllShortestPathsResponse,
    summary="Find ALL paths that tie for shortest length",
    description="""
    Finds every path that matches the minimum hop count between source and target.

    **Critical insight:** If 3 paths all take 4 hops, patching one
    vulnerability only removes 1 path. The attacker uses the other 2.

    Check `is_redundantly_exposed` on the response — if `true`,
    you have multiple equivalent attack routes and need to address all of them.
    """,
)
async def get_all_shortest_paths(
    source_id: str = Query(..., description="Starting node ID"),
    target_id: str = Query(..., description="Target node ID"),
    max_hops: int = Query(default=8, ge=1, le=15),
    limit: int = Query(default=10, le=50),
    service: TraversalService = Depends(get_traversal_service),
) -> AllShortestPathsResponse:
    return await service.find_all_shortest_paths(
        source_id=source_id,
        target_id=target_id,
        max_hops=max_hops,
        limit=limit,
    )


# ===========================================================================
# VULNERABLE HOSTS
# ===========================================================================

@router.get(
    "/vulnerable-hosts",
    response_model=VulnerableHostsResponse,
    summary="Get vulnerable hosts ranked by composite risk score",
    description="""
    Returns all hosts with vulnerabilities, ranked by a composite risk score.

    **Risk score factors:**
    - Max CVSS severity (0-10)
    - Number of exploitable vulnerabilities
    - Number of vulnerabilities with public exploits
    - Whether the host is internet-facing (+2.0 bonus)
    - Whether the host is a critical asset (+1.5 bonus)

    Use `min_cvss` to filter to high/critical severity only (7.0+).
    """,
)
async def get_vulnerable_hosts(
    min_cvss: float = Query(default=0.0, ge=0.0, le=10.0, description="Minimum CVSS score filter"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    service: TraversalService = Depends(get_traversal_service),
) -> VulnerableHostsResponse:
    return await service.find_vulnerable_hosts(
        min_cvss=min_cvss,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/vulnerable-hosts/unpatched",
    summary="Find hosts with available but unapplied patches",
    description="""
    Finds hosts that have vulnerabilities where patches EXIST but haven't been applied.

    These are the easiest wins for defenders —
    the fix exists, it just hasn't been deployed.

    Ordered by: most patchable vulnerabilities first.
    """,
)
async def get_unpatched_hosts(
    min_cvss: float = Query(default=7.0, ge=0.0, le=10.0),
    limit: int = Query(default=20, le=100),
    service: TraversalService = Depends(get_traversal_service),
):
    return await service.find_unpatched_critical_hosts(min_cvss=min_cvss, limit=limit)


# ===========================================================================
# BLAST RADIUS
# ===========================================================================

@router.get(
    "/blast-radius/{host_id}",
    response_model=BlastRadiusResponse,
    summary="Full blast radius analysis for a compromised host",
    description="""
    Answers the incident response question:
    **"This host is compromised — what's the damage?"**

    Returns:
    - Total affected nodes by type (Hosts, Databases, Services, Users)
    - Critical assets exposed
    - PII-containing systems exposed
    - Timeline: how many nodes reachable at each hop distance
    - Blast severity rating: LOW / MEDIUM / HIGH / CRITICAL

    **Blast severity is CRITICAL when:**
    3+ critical assets OR 2+ PII systems are reachable.
    """,
)
async def get_blast_radius(
    host_id: str = Path(..., description="ID of the compromised host"),
    max_hops: int = Query(default=4, ge=1, le=8, description="Traversal depth (4 is practical max)"),
    service: TraversalService = Depends(get_traversal_service),
) -> BlastRadiusResponse:
    return await service.get_blast_radius(host_id=host_id, max_hops=max_hops)


# ===========================================================================
# PRIVILEGE ESCALATION
# ===========================================================================

@router.get(
    "/escalation/chains",
    response_model=PrivilegeEscalationResponse,
    summary="Find all privilege escalation chains",
    description="""
    Finds every path from any host through vulnerabilities to an admin/root account.

    **Ordered by:** highest total CVSS first (most dangerous),
    then shortest chain (easiest to execute).

    Response includes:
    - Full chain: entry host → exploited CVEs → admin account
    - Risk level per chain (CRITICAL/HIGH/MEDIUM/LOW)
    - Whether the chain is fully automated (all exploits are weaponized)
    - Summary: how many unique hosts have escalation paths
    """,
)
async def get_escalation_chains(
    limit: int = Query(default=20, le=100),
    service: TraversalService = Depends(get_traversal_service),
) -> PrivilegeEscalationResponse:
    return await service.find_privilege_escalation_chains(limit=limit)


@router.get(
    "/escalation/to-root",
    response_model=EscalationToRootResponse,
    summary="Find internet-entry to root/admin escalation paths",
    description="""
    The most critical finding in any security assessment.

    Finds paths from internet-facing hosts directly to root/admin accounts.

    **`immediate_action_required` is set to `true` when:**
    A public exploit exists for a CVSS 9.0+ vulnerability on the path.
    This means any script-kiddie can become root with one command.
    """,
)
async def get_escalation_to_root(
    max_hops: int = Query(default=8, ge=1, le=15),
    limit: int = Query(default=10, le=50),
    service: TraversalService = Depends(get_traversal_service),
) -> EscalationToRootResponse:
    return await service.find_escalation_to_root(max_hops=max_hops, limit=limit)


@router.get(
    "/escalation/service-accounts",
    summary="Find service account privilege escalation paths",
    description="""
    Finds cases where compromising a service gives access to
    the same critical resources as an admin service account.

    Service account abuse is one of the most common real-world
    attack vectors — often overlooked because service accounts
    don't belong to a human.
    """,
)
async def get_service_account_escalation(
    limit: int = Query(default=20, le=100),
    service: TraversalService = Depends(get_traversal_service),
):
    return await service.find_service_account_escalation(limit=limit)


@router.get(
    "/escalation/cross-subnet",
    summary="Find cross-subnet lateral movement + escalation paths",
    description="""
    Finds the most severe enterprise attack pattern:
    Internet → DMZ host → pivot to internal subnet → become admin.

    This crosses network segmentation boundaries —
    indicates that firewall rules or network segmentation
    is insufficient to contain a breach.
    """,
)
async def get_cross_subnet_escalation(
    max_hops: int = Query(default=8, ge=1, le=15),
    limit: int = Query(default=10, le=50),
    service: TraversalService = Depends(get_traversal_service),
):
    return await service.find_cross_subnet_escalation(max_hops=max_hops, limit=limit)
