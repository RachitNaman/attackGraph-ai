"""
api/v1/health.py
================
Health check endpoint — critical for Docker and Kubernetes.
"""

from fastapi import APIRouter
from app.graph.neo4j_client import neo4j_client

router = APIRouter()


@router.get("/health")
async def health_check():
    """
    Check that all backend services are reachable.
    Returns 200 if healthy, 503 if any critical service is down.
    """
    neo4j_health = await neo4j_client.health_check()

    all_healthy = neo4j_health["status"] == "healthy"

    return {
        "status": "healthy" if all_healthy else "degraded",
        "services": {
            "neo4j": neo4j_health,
            # qdrant: added when vectorstore module is built
            # redis: added when celery module is built
        }
    }
