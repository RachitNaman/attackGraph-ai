"""
vectorstore/qdrant_client.py
=============================
Qdrant client — the ONLY file that imports qdrant_client library.

WHY VECTOR DB AT ALL?
Neo4j is brilliant at structure — "what connects to what".
But it knows nothing about MEANING.

When an analyst asks "find vulnerabilities similar to Log4Shell",
Neo4j cannot help — it does not understand semantic similarity.
Qdrant solves this by storing text as mathematical vectors
where similar meanings are close together in vector space.

WHAT GETS STORED IN QDRANT:
  CVE descriptions        -> "heap overflow in Apache allowing RCE..."
  Asset metadata text     -> "legacy SAP server, unpatched since 2019..."
  Threat intelligence     -> "APT29 uses spearphishing + credential theft..."
  Attack technique text   -> MITRE ATT&CK technique descriptions

WHAT DOES NOT GET STORED IN QDRANT:
  IP addresses            -> exact lookups, use Neo4j
  CVSS scores             -> numeric comparisons, use Neo4j
  Network topology        -> relationships, use Neo4j
  Port numbers            -> exact values, use Neo4j

THE RULE:
  EXACT match or NUMERIC comparison -> Neo4j
  SEMANTIC similarity or MEANING    -> Qdrant

WHY GRAPH TRAVERSAL BEFORE VECTOR RETRIEVAL:
  Step 1 - Neo4j finds STRUCTURAL context first:
           "Web server connects to app server which has CVE-2021-44228"
           You now know the exact CVE IDs on the attack path.

  Step 2 - Qdrant enriches with SEMANTIC context:
           "Tell me everything meaningful about CVE-2021-44228"
           Description, similar CVEs, threat actor usage, mitigations.

  You need the graph traversal first to know WHAT to look up in Qdrant.
  Without it you would be doing a blind semantic search with no anchor.
"""

import logging
from typing import Any
from qdrant_client import AsyncQdrantClient
from qdrant_client.models import (
    Distance,
    VectorParams,
    PointStruct,
    Filter,
    FieldCondition,
    MatchValue,
)

from app.core.config import settings
from app.core.exceptions import VectorStoreError

logger = logging.getLogger(__name__)


class QdrantClientManager:
    """
    Manages the Qdrant async client lifecycle.
    Single instance shared across the entire application.
    """

    def __init__(self) -> None:
        self._client: AsyncQdrantClient | None = None

    @staticmethod
    def _api_key() -> str | None:
        """Treat blank or comment-only local .env values as no API key."""
        api_key = settings.QDRANT_API_KEY.strip()
        if not api_key or api_key.startswith("#"):
            return None
        return api_key

    async def connect(self) -> None:
        """Initialize Qdrant client. Called once at FastAPI startup."""
        try:
            self._client = AsyncQdrantClient(
                host=settings.QDRANT_HOST,
                port=settings.QDRANT_PORT,
                grpc_port=settings.QDRANT_GRPC_PORT,
                api_key=self._api_key(),
                prefer_grpc=False,
                timeout=30,
            )
            await self._client.get_collections()
            logger.info("Qdrant connected successfully")
        except Exception as e:
            logger.error(f"Qdrant connection failed: {e}")
            raise VectorStoreError(f"Cannot connect to Qdrant: {e}") from e

    async def disconnect(self) -> None:
        """Close Qdrant client. Called at FastAPI shutdown."""
        if self._client:
            await self._client.close()
            self._client = None
            logger.info("Qdrant connection closed")

    @property
    def client(self) -> AsyncQdrantClient:
        if not self._client:
            raise VectorStoreError(
                "Qdrant client not initialized. Call connect() first."
            )
        return self._client

    async def health_check(self) -> dict:
        """Check Qdrant is reachable. Used by /health endpoint."""
        try:
            collections = await self._client.get_collections()
            return {
                "status": "healthy",
                "collections": len(collections.collections),
            }
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}

    async def ensure_collection(
        self,
        name: str,
        vector_size: int,
        distance: Distance = Distance.COSINE,
    ) -> None:
        """
        Create a collection if it does not already exist.
        Safe to call multiple times — idempotent.

        COSINE distance is best for text embeddings because
        it measures the ANGLE between vectors (semantic similarity)
        rather than absolute distance.
        """
        try:
            existing = await self._client.get_collections()
            existing_names = [c.name for c in existing.collections]

            if name not in existing_names:
                await self._client.create_collection(
                    collection_name=name,
                    vectors_config=VectorParams(
                        size=vector_size,
                        distance=distance,
                    ),
                )
                logger.info(f"Qdrant collection created: {name}")
            else:
                logger.debug(f"Qdrant collection already exists: {name}")

        except Exception as e:
            raise VectorStoreError(f"Failed to ensure collection '{name}': {e}") from e

    async def upsert_points(
        self,
        collection_name: str,
        points: list[PointStruct],
    ) -> None:
        """
        Insert or update vectors in a collection.
        UPSERT means update if ID exists, insert if not — idempotent.
        """
        try:
            await self._client.upsert(
                collection_name=collection_name,
                points=points,
                wait=True,
            )
            logger.debug(f"Upserted {len(points)} points to {collection_name}")
        except Exception as e:
            raise VectorStoreError(f"Upsert failed for '{collection_name}': {e}") from e

    async def search(
        self,
        collection_name: str,
        query_vector: list[float],
        top_k: int = 5,
        score_threshold: float = 0.5,
        filters: dict[str, Any] | None = None,
    ) -> list[dict]:
        """
        Search for semantically similar vectors.

        Returns top_k most similar points above score_threshold.
        Score is cosine similarity: 1.0 = identical, 0.0 = unrelated.
        """
        try:
            qdrant_filter = None
            if filters:
                conditions = [
                    FieldCondition(key=k, match=MatchValue(value=v))
                    for k, v in filters.items()
                ]
                qdrant_filter = Filter(must=conditions)

            results = await self._client.search(
                collection_name=collection_name,
                query_vector=query_vector,
                limit=top_k,
                score_threshold=score_threshold,
                query_filter=qdrant_filter,
                with_payload=True,
            )

            return [
                {
                    "id": str(hit.id),
                    "score": hit.score,
                    "payload": hit.payload or {},
                }
                for hit in results
            ]

        except Exception as e:
            raise VectorStoreError(f"Search failed in '{collection_name}': {e}") from e

    async def get_point(self, collection_name: str, point_id: str) -> dict | None:
        """Retrieve a specific point by ID."""
        try:
            results = await self._client.retrieve(
                collection_name=collection_name,
                ids=[point_id],
                with_payload=True,
                with_vectors=False,
            )
            return {"id": results[0].id, "payload": results[0].payload} if results else None
        except Exception as e:
            raise VectorStoreError(f"Get point failed: {e}") from e

    async def count_points(self, collection_name: str) -> int:
        """Return total number of vectors in a collection."""
        try:
            result = await self._client.count(collection_name=collection_name)
            return result.count
        except Exception:
            return 0


# Singleton instance
qdrant_manager = QdrantClientManager()
