"""
dependencies.py
===============
FastAPI Dependency Injection wiring.

All services are assembled here and injected into route handlers
via FastAPI's Depends() system.

ADDING A NEW SERVICE:
1. Create a get_xxx_service() function here
2. Import it in the route file
3. Add it as a parameter: service = Depends(get_xxx_service)

TESTING OVERRIDE:
    app.dependency_overrides[get_graph_service] = lambda: MockGraphService()
"""

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer

from app.graph.neo4j_client import neo4j_client, Neo4jClient
from app.vectorstore.qdrant_client import qdrant_manager, QdrantClientManager
from app.services.graph_service import GraphService
from app.services.traversal_service import TraversalService
from app.services.rag_service import RAGService
from app.services.graphrag_service import GraphRAGService
from app.services.account_service import account_service
from app.core.security import decode_access_token


# ---------------------------------------------------------------------------
# Infrastructure clients
# ---------------------------------------------------------------------------

def get_neo4j_client() -> Neo4jClient:
    """Provide the Neo4j client singleton."""
    return neo4j_client


def get_qdrant_client() -> QdrantClientManager:
    """Provide the Qdrant client singleton."""
    return qdrant_manager


# ---------------------------------------------------------------------------
# Service layer
# ---------------------------------------------------------------------------

def get_graph_service(
    client: Neo4jClient = Depends(get_neo4j_client),
) -> GraphService:
    """
    Provide GraphService with Neo4j client injected.
    Used by: api/v1/graph.py
    """
    return GraphService()


def get_traversal_service(
    client: Neo4jClient = Depends(get_neo4j_client),
) -> TraversalService:
    """
    Provide TraversalService with Neo4j client injected.
    Used by: api/v1/traversal.py
    """
    return TraversalService()


def get_rag_service(
    client: QdrantClientManager = Depends(get_qdrant_client),
) -> RAGService:
    """
    Provide RAGService with Qdrant client injected.
    Used by: api/v1/rag.py
    """
    return RAGService()


def get_graphrag_service(
    neo4j: Neo4jClient = Depends(get_neo4j_client),
    qdrant: QdrantClientManager = Depends(get_qdrant_client),
) -> GraphRAGService:
    """
    Provide GraphRAGService with both clients injected.
    Used by: api/v1/rag.py (analyze endpoint)
    """
    from app.services.graph_service import graph_service
    from app.services.traversal_service import traversal_service
    from app.services.rag_service import rag_service
    return GraphRAGService(
        graph_svc=graph_service,
        traversal_svc=traversal_service,
        rag_svc=rag_service,
    )


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------

# tokenUrl is just used to populate FastAPI's /docs "Authorize" button —
# it points Swagger UI at our actual login endpoint. It doesn't route
# traffic itself.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


async def get_current_account(token: str = Depends(oauth2_scheme)) -> dict:
    """
    Decode the bearer token and load the Account it refers to.

    Use this as a dependency on any route that requires a logged-in
    user:
        account: dict = Depends(get_current_account)

    Raises AuthError (-> 401 via the global exception handler) if the
    token is missing, invalid, expired, or refers to a deleted account.
    """
    payload = decode_access_token(token)
    account_id = payload["sub"]
    return await account_service.get_by_id(account_id)
