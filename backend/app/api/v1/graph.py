"""
api/v1/graph.py
===============
Graph API route handlers.

Route handlers have ONE job: validate input, call service, return response.
No business logic. No Cypher queries. No database calls.
"""

from fastapi import APIRouter, Depends, Query
from app.services.graph_service import GraphService
from app.dependencies import get_graph_service
from app.models.responses.graph import (
    HostResponse,
    AttackPathResponse,
    GraphSummaryResponse,
)

router = APIRouter()


@router.get("/summary", response_model=GraphSummaryResponse)
async def get_graph_summary(
    service: GraphService = Depends(get_graph_service),
):
    """Get counts of all node types and relationship types in the graph."""
    return await service.get_graph_summary()


@router.get("/hosts", response_model=list[HostResponse])
async def get_hosts(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, le=200),
    service: GraphService = Depends(get_graph_service),
):
    """Get paginated list of all hosts."""
    return await service.get_all_hosts(skip=skip, limit=limit)


@router.get("/hosts/internet-facing", response_model=list[HostResponse])
async def get_internet_facing_hosts(
    service: GraphService = Depends(get_graph_service),
):
    """Get all hosts directly exposed to the internet (primary attack surface)."""
    return await service.get_internet_facing_hosts()


@router.get("/hosts/{host_id}", response_model=HostResponse)
async def get_host(
    host_id: str,
    service: GraphService = Depends(get_graph_service),
):
    """Get a single host with its services and vulnerabilities."""
    return await service.get_host_by_id(host_id)


@router.get("/hosts/{host_id}/blast-radius")
async def get_blast_radius(
    host_id: str,
    service: GraphService = Depends(get_graph_service),
):
    """Calculate blast radius: what's reachable if this host is compromised?"""
    return await service.get_blast_radius(host_id)


@router.get("/attack-paths")
async def get_attack_paths(
    source_id: str = Query(..., description="ID of the source/attacker node"),
    target_id: str | None = Query(default=None, description="ID of the target node"),
    max_hops: int = Query(default=6, ge=1, le=10),
    limit: int = Query(default=10, le=50),
    service: GraphService = Depends(get_graph_service),
):
    """Find all attack paths from source to target."""
    return await service.find_attack_paths(
        source_id=source_id,
        target_id=target_id,
        max_hops=max_hops,
        limit=limit,
    )


@router.get("/attack-paths/to-database")
async def get_paths_to_database(
    max_hops: int = Query(default=6, ge=1, le=10),
    limit: int = Query(default=10, le=50),
    service: GraphService = Depends(get_graph_service),
):
    """Find all paths from internet-facing hosts to any database."""
    return await service.find_paths_to_database(max_hops=max_hops, limit=limit)


@router.get("/attack-paths/critical")
async def get_critical_paths(
    max_hops: int = Query(default=6, ge=1, le=10),
    limit: int = Query(default=10, le=50),
    service: GraphService = Depends(get_graph_service),
):
    """Get highest-risk attack paths ranked by composite score."""
    return await service.find_critical_paths(max_hops=max_hops, limit=limit)


@router.get("/risk/highest-risk-nodes")
async def get_highest_risk_nodes(
    limit: int = Query(default=20, le=100),
    service: GraphService = Depends(get_graph_service),
):
    """Get hosts ranked by composite risk score."""
    return await service.get_highest_risk_nodes(limit=limit)


@router.get("/vulnerabilities/exploitable")
async def get_exploitable_vulnerabilities(
    limit: int = Query(default=50, le=200),
    service: GraphService = Depends(get_graph_service),
):
    """Get all exploitable vulnerabilities with their affected hosts."""
    return await service.get_exploitable_vulnerabilities(limit=limit)
