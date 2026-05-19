"""
Graph Service
=============
The service layer for all Neo4j operations.

This is the ONLY layer that should be imported by:
- API route handlers (api/v1/*.py)
- LangGraph agent nodes (agents/nodes/*.py)
- The GraphRAG service (services/graphrag_service.py)

This layer should NEVER be imported by:
- The Neo4j client (graph/neo4j_client.py) — that's a lower layer
- Pydantic models (models/) — those are data containers only

RESPONSIBILITIES:
- Translate business questions into graph queries
- Call the Neo4j client with the right Cypher and parameters
- Transform raw Neo4j records into clean Python objects
- Handle graph-specific business logic (path scoring, deduplication)

NOT RESPONSIBILITIES:
- HTTP request/response handling (that's the API layer)
- LLM calls (that's the agent/graphrag layer)
- Embedding generation (that's the embedding service)
"""

import logging
import uuid
from typing import Any

from app.graph.neo4j_client import neo4j_client
from app.graph.queries import assets as asset_queries
from app.graph.queries import attack_paths as path_queries
from app.core.config import settings
from app.core.exceptions import GraphQueryError, AssetNotFoundError
from app.models.responses.graph import (
    HostResponse,
    ServiceResponse,
    VulnerabilityResponse,
    AttackPathResponse,
    GraphSummaryResponse,
)

logger = logging.getLogger(__name__)


class GraphService:
    """
    Service layer for graph database operations.

    All methods are async — they must be awaited by callers.
    All methods return typed Python objects, never raw Neo4j records.

    Dependency injection: this class receives the neo4j_client
    at construction time (injected via FastAPI's Depends system).
    This makes it testable — in tests, you can inject a mock client.
    """

    # ===========================================================================
    # HOST OPERATIONS
    # ===========================================================================

    async def create_host(
        self,
        ip_address: str,
        hostname: str = "",
        os: str = "",
        os_version: str = "",
        subnet: str = "",
        is_internet_facing: bool = False,
        is_critical: bool = False,
        asset_group: str = "Internal",
    ) -> HostResponse:
        """
        Create or update a Host node in the graph.

        Uses MERGE — safe to call multiple times with the same IP.
        The ID is deterministic based on IP so the same host
        is never duplicated even if ingested from multiple scanners.

        Args:
            ip_address: The host's IP address (required, used as basis for ID)
            hostname: Human-readable name
            os: Operating system name
            os_version: OS version string
            subnet: CIDR notation (e.g., "192.168.1.0/24")
            is_internet_facing: True if directly reachable from internet
            is_critical: True if this is a high-value target
            asset_group: Logical grouping ("DMZ", "Internal", "Cloud")

        Returns:
            HostResponse with the created/updated host data
        """
        host_id = f"host-{ip_address.replace('.', '-')}"

        try:
            results = await neo4j_client.execute_write(
                asset_queries.MERGE_HOST,
                {
                    "id": host_id,
                    "ip_address": ip_address,
                    "hostname": hostname or ip_address,
                    "os": os,
                    "os_version": os_version,
                    "subnet": subnet,
                    "is_internet_facing": is_internet_facing,
                    "is_critical": is_critical,
                    "asset_group": asset_group,
                }
            )

            if not results:
                raise GraphQueryError(f"Failed to create host: {ip_address}")

            host_data = results[0].get("h", {})
            logger.info(f"Host merged: {host_id} ({ip_address})")
            return HostResponse.from_neo4j(host_data)

        except Exception as e:
            logger.error(f"Error creating host {ip_address}: {e}")
            raise

    async def get_host_by_id(self, host_id: str) -> HostResponse:
        """Retrieve a single host with its services and vulnerabilities."""
        results = await neo4j_client.execute_read(
            asset_queries.GET_HOST_BY_ID,
            {"id": host_id}
        )

        if not results:
            raise AssetNotFoundError(f"Host not found: {host_id}")

        record = results[0]
        return HostResponse.from_neo4j(
            record["h"],
            services=record.get("services", []),
            vulnerabilities=record.get("vulnerabilities", [])
        )

    async def get_host_by_ip(self, ip_address: str) -> HostResponse:
        """Retrieve a host by its IP address."""
        results = await neo4j_client.execute_read(
            asset_queries.GET_HOST_BY_IP,
            {"ip_address": ip_address}
        )

        if not results:
            raise AssetNotFoundError(f"Host not found with IP: {ip_address}")

        return HostResponse.from_neo4j(results[0]["h"])

    async def get_all_hosts(self, skip: int = 0, limit: int = 100) -> list[HostResponse]:
        """Retrieve paginated list of all hosts."""
        results = await neo4j_client.execute_read(
            asset_queries.GET_ALL_HOSTS,
            {"skip": skip, "limit": limit}
        )
        return [HostResponse.from_neo4j(r["h"], vuln_count=r.get("vuln_count", 0)) for r in results]

    async def get_internet_facing_hosts(self) -> list[HostResponse]:
        """Get all hosts directly exposed to the internet — the primary attack surface."""
        results = await neo4j_client.execute_read(
            asset_queries.GET_INTERNET_FACING_HOSTS
        )
        return [
            HostResponse.from_neo4j(r["h"], services=r.get("services", []), vuln_count=r.get("vuln_count", 0))
            for r in results
        ]

    # ===========================================================================
    # SERVICE OPERATIONS
    # ===========================================================================

    async def create_service(
        self,
        host_id: str,
        port: int,
        protocol: str,
        name: str = "",
        version: str = "",
        banner: str = "",
        is_encrypted: bool = False,
    ) -> ServiceResponse:
        """
        Create a Service node and link it to its Host with a RUNS relationship.

        The service ID is deterministic: host + port + protocol combination.
        """
        service_id = f"svc-{host_id}-{port}-{protocol}"

        await neo4j_client.execute_write(
            asset_queries.MERGE_SERVICE,
            {
                "id": service_id,
                "name": name,
                "port": port,
                "protocol": protocol,
                "version": version,
                "banner": banner,
                "is_encrypted": is_encrypted,
            }
        )

        # Create the RUNS relationship: Host -[:RUNS]-> Service
        await neo4j_client.execute_write(
            asset_queries.CREATE_RUNS_RELATIONSHIP,
            {"host_id": host_id, "service_id": service_id}
        )

        logger.info(f"Service created: {service_id} on {host_id}")
        return ServiceResponse(
            id=service_id,
            host_id=host_id,
            name=name,
            port=port,
            protocol=protocol,
            version=version,
            is_encrypted=is_encrypted,
        )

    # ===========================================================================
    # VULNERABILITY OPERATIONS
    # ===========================================================================

    async def create_vulnerability(
        self,
        cve_id: str,
        description: str,
        cvss_score: float,
        severity: str,
        affected_component: str = "",
        cwe_id: str = "",
        cvss_vector: str = "",
        is_exploitable: bool = False,
        has_public_exploit: bool = False,
        exploit_maturity: str = "unproven",
        patch_available: bool = False,
        published_date: str = "",
    ) -> VulnerabilityResponse:
        """Create or update a Vulnerability node."""
        vuln_id = f"vuln-{cve_id.lower()}"

        results = await neo4j_client.execute_write(
            asset_queries.MERGE_VULNERABILITY,
            {
                "id": vuln_id,
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "severity": severity,
                "cwe_id": cwe_id,
                "affected_component": affected_component,
                "is_exploitable": is_exploitable,
                "has_public_exploit": has_public_exploit,
                "exploit_maturity": exploit_maturity,
                "patch_available": patch_available,
                "published_date": published_date,
            }
        )

        logger.info(f"Vulnerability merged: {cve_id} (CVSS: {cvss_score})")
        return VulnerabilityResponse(
            id=vuln_id,
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            severity=severity,
            is_exploitable=is_exploitable,
            has_public_exploit=has_public_exploit,
        )

    async def link_vulnerability_to_host(
        self,
        host_id: str,
        cve_id: str,
        scanner: str = "manual",
        confirmed: bool = True,
    ) -> None:
        """
        Create HAS_VULNERABILITY relationship between a Host and a Vulnerability.

        Call create_host() and create_vulnerability() first —
        both nodes must exist before a relationship can be created.
        """
        await neo4j_client.execute_write(
            asset_queries.CREATE_HAS_VULNERABILITY_RELATIONSHIP,
            {
                "host_id": host_id,
                "cve_id": cve_id,
                "scanner": scanner,
                "confirmed": confirmed,
            }
        )
        logger.info(f"Linked: {host_id} -[:HAS_VULNERABILITY]-> {cve_id}")

    async def get_exploitable_vulnerabilities(self, limit: int = 50) -> list[dict]:
        """Get all exploitable vulnerabilities with their affected hosts."""
        return await neo4j_client.execute_read(
            asset_queries.GET_EXPLOITABLE_VULNERABILITIES,
            {"limit": limit}
        )

    # ===========================================================================
    # ATTACK PATH OPERATIONS
    # ===========================================================================

    async def find_attack_paths(
        self,
        source_id: str,
        target_id: str | None = None,
        max_hops: int | None = None,
        limit: int = 20,
    ) -> list[AttackPathResponse]:
        """
        Find all attack paths from a source node to a target.

        This is the core graph traversal operation for attack analysis.
        If target_id is None, finds all paths from source to any node.

        Args:
            source_id: ID of the starting node (typically an internet-facing host)
            target_id: ID of the destination node (database, admin user, etc.)
            max_hops: Maximum traversal depth (default from config)
            limit: Maximum number of paths to return

        Returns:
            List of AttackPathResponse objects, sorted by hop count
        """
        max_hops = max_hops or settings.MAX_ATTACK_PATH_HOPS

        results = await neo4j_client.execute_read(
            path_queries.FIND_ALL_ATTACK_PATHS,
            {
                "source_id": source_id,
                "target_id": target_id,
                "max_hops": max_hops,
                "limit": limit,
            }
        )

        paths = []
        for record in results:
            path = AttackPathResponse(
                nodes=record.get("nodes", []),
                relationship_types=record.get("relationship_types", []),
                hop_count=record.get("hop_count", 0),
                risk_score=0.0,  # Calculated by scoring service
            )
            paths.append(path)

        logger.info(f"Found {len(paths)} attack paths from {source_id} to {target_id}")
        return paths

    async def find_paths_to_database(self, max_hops: int | None = None, limit: int = 10) -> list[dict]:
        """
        Find all paths from internet-facing hosts to any Database node.

        This directly answers "How can an attacker reach the database?"
        """
        max_hops = max_hops or settings.MAX_ATTACK_PATH_HOPS

        results = await neo4j_client.execute_read(
            path_queries.FIND_PATHS_TO_DATABASE,
            {"max_hops": max_hops, "limit": limit}
        )

        logger.info(f"Found {len(results)} paths to database nodes")
        return results

    async def find_critical_paths(self, max_hops: int | None = None, limit: int = 10) -> list[dict]:
        """Find highest-risk paths using composite scoring."""
        max_hops = max_hops or settings.MAX_ATTACK_PATH_HOPS
        return await neo4j_client.execute_read(
            path_queries.FIND_CRITICAL_PATHS,
            {"max_hops": max_hops, "limit": limit}
        )

    async def find_paths_through_vulnerability(
        self,
        min_cvss_score: float = 7.0,
        limit: int = 20,
    ) -> list[dict]:
        """Find attack paths that exploit a vulnerability above the CVSS threshold."""
        return await neo4j_client.execute_read(
            path_queries.FIND_PATHS_THROUGH_VULNERABILITY,
            {"min_cvss_score": min_cvss_score, "limit": limit}
        )

    async def get_blast_radius(self, host_id: str) -> dict:
        """
        Calculate the blast radius of a compromised host.
        Returns how many nodes of each type are reachable from this host.
        """
        results = await neo4j_client.execute_read(
            path_queries.GET_BLAST_RADIUS,
            {"host_id": host_id}
        )
        return {
            "host_id": host_id,
            "reachable_nodes": results,
            "total_reachable": sum(r.get("count", 0) for r in results),
        }

    async def get_highest_risk_nodes(self, limit: int = 20) -> list[dict]:
        """Get hosts ranked by composite risk score."""
        return await neo4j_client.execute_read(
            path_queries.GET_HIGHEST_RISK_NODES,
            {"limit": limit}
        )

    # ===========================================================================
    # BULK INGESTION OPERATIONS
    # ===========================================================================

    async def bulk_ingest_hosts(self, hosts: list[dict]) -> int:
        """
        Ingest a large batch of hosts in a single transaction.

        Call this from the ingestion service after parsing Nmap output.
        Much faster than calling create_host() in a loop.

        Args:
            hosts: List of host dicts matching the BULK_MERGE_HOSTS query schema

        Returns:
            Number of hosts merged
        """
        if not hosts:
            return 0

        # Add deterministic IDs if not present
        for host in hosts:
            if "id" not in host:
                host["id"] = f"host-{host['ip_address'].replace('.', '-')}"
            # Set defaults for optional fields
            host.setdefault("hostname", host["ip_address"])
            host.setdefault("os", "")
            host.setdefault("subnet", "")
            host.setdefault("is_internet_facing", False)
            host.setdefault("is_critical", False)

        results = await neo4j_client.execute_write(
            asset_queries.BULK_MERGE_HOSTS,
            {"rows": hosts}
        )

        merged = results[0].get("merged_count", 0) if results else len(hosts)
        logger.info(f"Bulk ingested {merged} hosts")
        return merged

    async def bulk_ingest_vulnerabilities(self, vulnerabilities: list[dict]) -> int:
        """Ingest a batch of vulnerabilities in a single transaction."""
        if not vulnerabilities:
            return 0

        for vuln in vulnerabilities:
            if "id" not in vuln:
                vuln["id"] = f"vuln-{vuln['cve_id'].lower()}"
            vuln.setdefault("description", "")
            vuln.setdefault("cvss_score", 0.0)
            vuln.setdefault("severity", "UNKNOWN")
            vuln.setdefault("is_exploitable", False)
            vuln.setdefault("has_public_exploit", False)

        results = await neo4j_client.execute_write(
            asset_queries.BULK_MERGE_VULNERABILITIES,
            {"rows": vulnerabilities}
        )

        merged = results[0].get("merged_count", 0) if results else len(vulnerabilities)
        logger.info(f"Bulk ingested {merged} vulnerabilities")
        return merged

    async def bulk_link_vulnerabilities(self, links: list[dict]) -> int:
        """
        Bulk create HAS_VULNERABILITY relationships.

        Args:
            links: List of {host_id, cve_id, scanner, confirmed} dicts
        """
        if not links:
            return 0

        for link in links:
            link.setdefault("scanner", "unknown")
            link.setdefault("confirmed", True)

        results = await neo4j_client.execute_write(
            asset_queries.BULK_CREATE_HOST_VULNERABILITY_RELS,
            {"rows": links}
        )

        merged = results[0].get("merged_count", 0) if results else len(links)
        logger.info(f"Bulk linked {merged} host-vulnerability relationships")
        return merged

    # ===========================================================================
    # GRAPH STATISTICS
    # ===========================================================================

    async def get_graph_summary(self) -> GraphSummaryResponse:
        """Return counts of all node types and relationship types."""
        node_counts = await neo4j_client.execute_read(path_queries.GET_GRAPH_SUMMARY)
        rel_counts = await neo4j_client.execute_read(path_queries.GET_RELATIONSHIP_SUMMARY)

        return GraphSummaryResponse(
            node_counts={r["label"]: r["count"] for r in node_counts if r.get("label")},
            relationship_counts={r["relationship_type"]: r["count"] for r in rel_counts},
        )

    async def get_attack_surface_summary(self) -> list[dict]:
        """Return all internet-facing hosts with their exposure metrics."""
        return await neo4j_client.execute_read(
            path_queries.GET_NETWORK_ATTACK_SURFACE
        )


# ---------------------------------------------------------------------------
# Singleton instance — imported and used via FastAPI's dependency injection
# ---------------------------------------------------------------------------
graph_service = GraphService()
