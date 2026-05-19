"""
dependencies.py
===============
FastAPI Dependency Injection wiring.

This is where all services are assembled and made available
to route handlers via FastAPI's Depends() system.

HOW DEPENDS() WORKS:
    @router.get("/hosts")
    async def get_hosts(service: GraphService = Depends(get_graph_service)):
        return await service.get_all_hosts()

FastAPI sees `Depends(get_graph_service)`, calls get_graph_service(),
and passes the result as the `service` argument automatically.
You never call get_graph_service() yourself in route handlers.

WHY THIS PATTERN?
- Easy to swap implementations (swap real Neo4j for mock in tests)
- Single place to control how services are created
- Services get the right clients injected automatically
"""

from fastapi import Depends
from app.graph.neo4j_client import neo4j_client, Neo4jClient
from app.services.graph_service import GraphService


def get_neo4j_client() -> Neo4jClient:
    """Provide the Neo4j client singleton."""
    return neo4j_client


def get_graph_service(
    client: Neo4jClient = Depends(get_neo4j_client),
) -> GraphService:
    """
    Provide a GraphService instance with the Neo4j client injected.

    In tests, you can override this:
        app.dependency_overrides[get_graph_service] = lambda: MockGraphService()
    """
    return GraphService()
