"""
api/v1/health.py — System health check endpoint.
"""

from fastapi import APIRouter
from app.graph.neo4j_client import neo4j_client
from app.vectorstore.qdrant_client import qdrant_manager

router = APIRouter()


@router.get("/health")
async def health_check():
    """Check all backend services are reachable."""
    neo4j_health = await neo4j_client.health_check()
    qdrant_health = await qdrant_manager.health_check()

    all_healthy = (
        neo4j_health["status"] == "healthy"
        and qdrant_health["status"] == "healthy"
    )

    return {
        "status": "healthy" if all_healthy else "degraded",
        "services": {
            "neo4j": neo4j_health,
            "qdrant": qdrant_health,
        }
    }
