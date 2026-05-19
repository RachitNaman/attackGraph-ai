"""
services/traversal_service.py
==============================
Service layer for all graph traversal operations.

WHY SEPARATE FROM graph_service.py?
- graph_service.py handles CRUD: creating hosts, services, vulnerabilities
- traversal_service.py handles ANALYSIS: reachability, paths, escalation chains
- Each service stays focused and manageable
- LangGraph agents import traversal_service for analysis operations
- Ingestion pipeline imports graph_service for write operations

This service is READ-ONLY — it never writes to the graph.
All methods return clean Pydantic response objects.
"""

import logging
from app.graph.neo4j_client import neo4j_client
from app.graph.queries import traversal as traversal_queries
from app.core.config import settings
from app.core.exceptions import AssetNotFoundError, GraphQueryError
from app.models.responses.traversal import (
    ReachableNode,
    ReachableSystemsResponse,
    ShortestPathResponse,
    AllShortestPathsResponse,
    VulnerableHostDetail,
    VulnerableHostsResponse,
    BlastRadiusNodeType,
    BlastRadiusTimelineEntry,
    BlastRadiusResponse,
    PrivilegeEscalationChain,
    PrivilegeEscalationResponse,
    EscalationToRootEntry,
    EscalationToRootResponse,
)

logger = logging.getLogger(__name__)


class TraversalService:
    """
    Read-only service for graph traversal and attack path analysis.

    All methods are async. All return typed Pydantic objects.
    Never writes to the database — pure analysis layer.
    """

    def _query_with_max_hops(self, query: str, max_hops: int) -> str:
        """
        Neo4j requires variable-length path bounds to be integer literals.
        Validate before substituting so callers cannot inject Cypher.
        """
        max_hops = int(max_hops)
        if max_hops < 1 or max_hops > 50:
            raise GraphQueryError("max_hops must be between 1 and 50")

        return query.replace("$max_hops", str(max_hops))

    # ===========================================================================
    # REACHABLE SYSTEMS
    # ===========================================================================

    async def find_reachable_systems(
        self,
        host_id: str,
        max_hops: int | None = None,
    ) -> ReachableSystemsResponse:
        """
        Find all nodes reachable from a given host.

        This is the core "blast radius preview" query —
        it shows what an attacker can potentially reach
        if they compromise the specified host.

        Args:
            host_id: The starting host node ID
            max_hops: Maximum traversal depth (defaults to config value)

        Returns:
            ReachableSystemsResponse with all reachable nodes and summary counts
        """
        max_hops = max_hops or settings.MAX_ATTACK_PATH_HOPS

        results = await neo4j_client.execute_read(
            self._query_with_max_hops(traversal_queries.FIND_REACHABLE_SYSTEMS, max_hops),
            {"host_id": host_id}
        )

        if not results and max_hops > 1:
            # No results might mean the host_id doesn't exist
            # Try to distinguish "host not found" from "nothing reachable"
            check = await neo4j_client.execute_read(
                "MATCH (h:Host {id: $id}) RETURN h.id AS id",
                {"id": host_id}
            )
            if not check:
                raise AssetNotFoundError(f"Host not found: {host_id}")

        reachable_nodes = [
            ReachableNode(
                id=r["id"] or "",
                label=r["label"] or "Unknown",
                name=r["name"] or r["id"] or "",
                ip_address=r.get("ip_address") or "",
                is_critical=r.get("is_critical") or False,
                cvss_score=r.get("cvss_score"),
                min_hops=r["min_hops"],
            )
            for r in results
            if r.get("id")
        ]

        response = ReachableSystemsResponse(
            source_host_id=host_id,
            total_reachable=len(reachable_nodes),
            max_hops_used=max_hops,
            reachable_nodes=reachable_nodes,
        )

        logger.info(
            f"Reachable systems from {host_id}: "
            f"{len(reachable_nodes)} nodes within {max_hops} hops"
        )

        return response.compute_summary()

    async def find_reachable_by_type(
        self,
        host_id: str,
        node_type: str,
        max_hops: int | None = None,
        limit: int = 50,
    ) -> list[ReachableNode]:
        """
        Find reachable nodes of a specific type from a host.

        e.g. node_type="Database" → all databases the attacker can reach.
        e.g. node_type="User"     → all user accounts reachable.

        Args:
            host_id: Starting host
            node_type: Neo4j label to filter by (Host, Service, Database, User)
            max_hops: Maximum traversal depth
            limit: Maximum results to return
        """
        max_hops = max_hops or settings.MAX_ATTACK_PATH_HOPS

        results = await neo4j_client.execute_read(
            self._query_with_max_hops(traversal_queries.FIND_REACHABLE_BY_TYPE, max_hops),
            {"host_id": host_id, "node_type": node_type, "limit": limit}
        )

        return [
            ReachableNode(
                id=r["id"] or "",
                label=r["label"] or node_type,
                name=r["name"] or "",
                ip_address=r.get("ip_address") or "",
                is_critical=r.get("is_critical") or False,
                min_hops=r["min_hops"],
            )
            for r in results
        ]

    async def find_nodes_that_reach_target(
        self,
        target_id: str,
        max_hops: int | None = None,
    ) -> list[dict]:
        """
        REVERSE traversal — find all internet-facing hosts that can reach a target.

        Answers: "How many entry points lead to this asset?"
        If 10 internet-facing hosts can reach your database,
        you have 10 attack surfaces to protect.
        """
        max_hops = max_hops or settings.MAX_ATTACK_PATH_HOPS

        results = await neo4j_client.execute_read(
            self._query_with_max_hops(traversal_queries.FIND_NODES_THAT_CAN_REACH_TARGET, max_hops),
            {"target_id": target_id}
        )

        logger.info(f"Found {len(results)} entry points that can reach {target_id}")
        return results

    # ===========================================================================
    # SHORTEST PATH
    # ===========================================================================

    async def find_shortest_path(
        self,
        source_id: str,
        target_id: str,
        max_hops: int | None = None,
    ) -> ShortestPathResponse:
        """
        Find the shortest path (minimum hops) between two nodes.

        Uses BFS internally via Neo4j's shortestPath() function.
        BFS guarantees the MINIMUM hop count path is returned.

        WHY SHORTEST PATH MATTERS:
        The shortest path is the easiest route for an attacker.
        Fewer hops = fewer things that can go wrong for the attacker
        = higher probability of success.
        Security teams should prioritize breaking the shortest path first.

        Args:
            source_id: Starting node ID (attacker's entry point)
            target_id: Target node ID (what attacker wants to reach)
            max_hops: Hard cap on path length

        Returns:
            ShortestPathResponse — found=False if no path exists
        """
        max_hops = max_hops or settings.MAX_ATTACK_PATH_HOPS

        results = await neo4j_client.execute_read(
            self._query_with_max_hops(traversal_queries.FIND_SHORTEST_PATH_BETWEEN, max_hops),
            {"source_id": source_id, "target_id": target_id}
        )

        if not results:
            logger.info(f"No path found from {source_id} to {target_id}")
            return ShortestPathResponse(
                source_id=source_id,
                target_id=target_id,
                found=False,
            )

        record = results[0]
        nodes = record.get("nodes", [])
        relationships = record.get("relationships", [])

        # Extract CVEs from path nodes
        cve_ids = [
            n["id"] for n in nodes
            if n.get("label") == "Vulnerability"
        ]

        max_cvss = max(
            (n.get("cvss_score") or 0.0 for n in nodes if n.get("cvss_score")),
            default=0.0
        )

        logger.info(
            f"Shortest path {source_id} → {target_id}: "
            f"{record.get('hop_count', 0)} hops"
        )

        return ShortestPathResponse(
            source_id=source_id,
            target_id=target_id,
            found=True,
            hop_count=record.get("hop_count", 0),
            nodes=nodes,
            relationships=relationships,
            vulnerabilities_on_path=cve_ids,
            max_cvss_on_path=max_cvss,
        )

    async def find_all_shortest_paths(
        self,
        source_id: str,
        target_id: str,
        max_hops: int | None = None,
        limit: int = 10,
    ) -> AllShortestPathsResponse:
        """
        Find ALL paths that tie for the shortest length.

        WHY THIS IS CRITICAL:
        If 3 paths all take 4 hops, patching one vulnerability
        only removes 1 path. The attacker still has 2 others.
        You need to see all of them to understand true exposure.

        The is_redundantly_exposed flag on the response tells you
        immediately if you have this problem.
        """
        max_hops = max_hops or settings.MAX_ATTACK_PATH_HOPS

        results = await neo4j_client.execute_read(
            self._query_with_max_hops(traversal_queries.FIND_ALL_SHORTEST_PATHS, max_hops),
            {"source_id": source_id, "target_id": target_id, "limit": limit}
        )

        if not results:
            return AllShortestPathsResponse(
                source_id=source_id,
                target_id=target_id,
                shortest_hop_count=0,
                total_shortest_paths=0,
                paths=[],
            )

        paths = [
            ShortestPathResponse(
                source_id=source_id,
                target_id=target_id,
                found=True,
                hop_count=r.get("hop_count", 0),
                nodes=r.get("nodes", []),
                relationships=r.get("relationships", []),
            )
            for r in results
        ]

        return AllShortestPathsResponse(
            source_id=source_id,
            target_id=target_id,
            shortest_hop_count=results[0].get("hop_count", 0),
            total_shortest_paths=len(paths),
            paths=paths,
        )

    # ===========================================================================
    # VULNERABLE HOSTS
    # ===========================================================================

    async def find_vulnerable_hosts(
        self,
        min_cvss: float = 0.0,
        page: int = 1,
        page_size: int = 20,
    ) -> VulnerableHostsResponse:
        """
        Get all vulnerable hosts ranked by composite risk score.

        Risk score factors:
        - Max CVSS severity (how bad is the worst vulnerability?)
        - Exploitable count (how many are actively exploitable?)
        - Public exploit count (how many have Metasploit modules?)
        - Internet facing bonus (directly reachable = higher risk)
        - Critical asset bonus (high-value target = higher priority)

        Args:
            min_cvss: Minimum CVSS score filter (0.0 = all, 7.0 = high+)
            page: Page number for pagination
            page_size: Results per page
        """
        skip = (page - 1) * page_size

        results = await neo4j_client.execute_read(
            traversal_queries.FIND_VULNERABLE_HOSTS,
            {"min_cvss": min_cvss, "skip": skip, "limit": page_size}
        )

        hosts = [
            VulnerableHostDetail(
                host_id=r["host_id"],
                hostname=r.get("hostname") or "",
                ip_address=r.get("ip_address") or "",
                os=r.get("os") or "",
                subnet=r.get("subnet") or "",
                is_internet_facing=r.get("is_internet_facing") or False,
                is_critical=r.get("is_critical") or False,
                asset_group=r.get("asset_group") or "",
                total_vulns=r.get("total_vulns") or 0,
                max_cvss=r.get("max_cvss") or 0.0,
                exploitable_count=r.get("exploitable_count") or 0,
                public_exploit_count=r.get("public_exploit_count") or 0,
                risk_score=r.get("risk_score") or 0.0,
                vulnerabilities=r.get("vulnerabilities") or [],
            )
            for r in results
        ]

        logger.info(f"Found {len(hosts)} vulnerable hosts (min CVSS: {min_cvss})")

        return VulnerableHostsResponse(
            total=len(hosts),
            page=page,
            page_size=page_size,
            min_cvss_filter=min_cvss,
            hosts=hosts,
        )

    async def find_unpatched_critical_hosts(
        self,
        min_cvss: float = 7.0,
        limit: int = 20,
    ) -> list[dict]:
        """
        Find hosts with unpatched vulnerabilities where patches exist.

        These are the easiest wins for defenders —
        patch available but not applied.
        """
        return await neo4j_client.execute_read(
            traversal_queries.FIND_UNPATCHED_CRITICAL_HOSTS,
            {"min_cvss": min_cvss, "limit": limit}
        )

    # ===========================================================================
    # BLAST RADIUS
    # ===========================================================================

    async def get_blast_radius(
        self,
        host_id: str,
        max_hops: int = 4,
    ) -> BlastRadiusResponse:
        """
        Full blast radius analysis for a compromised host.

        Combines three queries:
        1. Detailed breakdown by node type
        2. Timeline (expansion per hop)
        3. Critical assets specifically

        This is what a security team needs in the first 15 minutes
        of an incident response.

        Args:
            host_id: The compromised host's ID
            max_hops: How deep to traverse (default 4 — practical limit)
        """
        # Run all three queries concurrently would be ideal —
        # for now running sequentially for simplicity
        detail_results = await neo4j_client.execute_read(
            self._query_with_max_hops(traversal_queries.FIND_BLAST_RADIUS_DETAIL, max_hops),
            {"host_id": host_id}
        )

        timeline_results = await neo4j_client.execute_read(
            self._query_with_max_hops(traversal_queries.FIND_BLAST_RADIUS_TIMELINE, max_hops),
            {"host_id": host_id}
        )

        critical_results = await neo4j_client.execute_read(
            self._query_with_max_hops(traversal_queries.FIND_CRITICAL_ASSETS_IN_BLAST_RADIUS, max_hops),
            {"host_id": host_id}
        )

        # Build node type breakdown
        by_node_type = [
            BlastRadiusNodeType(
                node_type=r.get("node_type") or "Unknown",
                affected_count=r.get("affected_count") or 0,
                critical_count=r.get("critical_count") or 0,
                pii_count=r.get("pii_count") or 0,
                sample_nodes=r.get("sample_nodes") or [],
            )
            for r in detail_results
        ]

        # Build timeline
        timeline = [
            BlastRadiusTimelineEntry(
                hops_from_source=r.get("hops_from_source") or 0,
                nodes_reachable=r.get("nodes_reachable") or 0,
                node_types_at_distance=r.get("node_types_at_distance") or [],
                examples=r.get("examples") or [],
            )
            for r in timeline_results
        ]

        # Totals
        total_affected = sum(b.affected_count for b in by_node_type)
        total_critical = sum(b.critical_count for b in by_node_type)
        total_pii = sum(b.pii_count for b in by_node_type)

        response = BlastRadiusResponse(
            compromised_host_id=host_id,
            max_hops_analyzed=max_hops,
            total_affected_nodes=total_affected,
            total_critical_assets=total_critical,
            total_pii_systems=total_pii,
            by_node_type=by_node_type,
            timeline=timeline,
            critical_assets_exposed=critical_results,
        )

        logger.info(
            f"Blast radius for {host_id}: "
            f"{total_affected} nodes, {total_critical} critical, {total_pii} PII"
        )

        return response.compute_severity()

    # ===========================================================================
    # PRIVILEGE ESCALATION
    # ===========================================================================

    async def find_privilege_escalation_chains(
        self,
        limit: int = 20,
    ) -> PrivilegeEscalationResponse:
        """
        Find all privilege escalation chains in the network.

        A chain is a path from any host through vulnerabilities
        to an admin/root user account.

        Ordered by: highest total CVSS (most dangerous) first,
        then shortest chain (easiest to execute) first.

        Returns full PrivilegeEscalationResponse with summary stats.
        """
        results = await neo4j_client.execute_read(
            traversal_queries.FIND_PRIVILEGE_ESCALATION_CHAINS,
            {"limit": limit}
        )

        chains = [
            PrivilegeEscalationChain(
                entry_host_id=r.get("entry_host_id") or "",
                entry_hostname=r.get("entry_hostname") or "",
                entry_ip=r.get("entry_ip") or "",
                entry_internet_facing=r.get("entry_internet_facing") or False,
                chain_nodes=r.get("chain_nodes") or [],
                chain_relationships=r.get("chain_relationships") or [],
                chain_length=r.get("chain_length") or 0,
                target_username=r.get("target_username") or "",
                is_admin=r.get("is_admin") or False,
                exploited_vulnerabilities=r.get("exploited_vulnerabilities") or [],
                total_cvss=r.get("total_cvss") or 0.0,
            )
            for r in results
        ]

        logger.info(f"Found {len(chains)} privilege escalation chains")

        return PrivilegeEscalationResponse(
            total_chains_found=len(chains),
            chains=chains,
        ).compute_summary()

    async def find_escalation_to_root(
        self,
        max_hops: int | None = None,
        limit: int = 10,
    ) -> EscalationToRootResponse:
        """
        Find direct internet → root/admin escalation paths.

        These are the MOST CRITICAL findings in any penetration test.
        An internet-facing host where a public exploit leads directly
        to root access requires IMMEDIATE patching.

        The immediate_action_required flag is set when:
        - A public exploit exists AND
        - CVSS score >= 9.0 (Critical)
        """
        max_hops = max_hops or settings.MAX_ATTACK_PATH_HOPS

        results = await neo4j_client.execute_read(
            self._query_with_max_hops(traversal_queries.FIND_ESCALATION_TO_ROOT, max_hops),
            {"limit": limit}
        )

        entries = [
            EscalationToRootEntry(
                entry_id=r.get("entry_id") or "",
                entry_hostname=r.get("entry_hostname") or "",
                entry_ip=r.get("entry_ip") or "",
                escalation_cve=r.get("escalation_cve") or "",
                cvss_score=r.get("cvss_score") or 0.0,
                exploit_maturity=r.get("exploit_maturity") or "unproven",
                has_public_exploit=r.get("has_public_exploit") or False,
                admin_username=r.get("admin_username") or "",
                admin_id=r.get("admin_id") or "",
                full_path=r.get("full_path") or [],
                hops=r.get("hops") or 0,
            )
            for r in results
        ]

        logger.info(
            f"Found {len(entries)} internet-to-root escalation paths"
        )

        return EscalationToRootResponse(
            total_found=len(entries),
            entries=entries,
        ).compute_flags()

    async def find_service_account_escalation(
        self,
        limit: int = 20,
    ) -> list[dict]:
        """
        Find service account abuse escalation paths.

        Service accounts often have excessive permissions.
        This finds cases where compromising a service gives
        indirect access to the same critical resources as an admin account.
        """
        return await neo4j_client.execute_read(
            traversal_queries.FIND_SERVICE_ACCOUNT_ESCALATION,
            {"limit": limit}
        )

    async def find_cross_subnet_escalation(
        self,
        max_hops: int | None = None,
        limit: int = 10,
    ) -> list[dict]:
        """
        Find lateral movement + privilege escalation across subnet boundaries.

        The most severe enterprise attack pattern:
        Internet → DMZ host → pivot to internal subnet → become admin
        """
        max_hops = max_hops or settings.MAX_ATTACK_PATH_HOPS

        return await neo4j_client.execute_read(
            self._query_with_max_hops(traversal_queries.FIND_CROSS_SUBNET_ESCALATION, max_hops),
            {"limit": limit}
        )


# Singleton instance
traversal_service = TraversalService()
