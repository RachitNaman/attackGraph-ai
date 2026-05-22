"""
vectorstore/embeddings.py
==========================
Gemini embedding generation — converts text to vectors.

HOW EMBEDDINGS WORK (simply):
Text goes in -> mathematical vector comes out.
"Apache Log4j Remote Code Execution" -> [0.23, -0.41, 0.88, ... 768 numbers]

Similar texts produce similar vectors.
"Log4Shell vulnerability" and "CVE-2021-44228 RCE" would produce
vectors that are very close together in 768-dimensional space.

This is how semantic search works — instead of matching keywords,
Qdrant finds vectors that POINT IN THE SAME DIRECTION.

GEMINI TEXT-EMBEDDING-004:
- Produces 768-dimensional vectors
- Best-in-class for cybersecurity text
- Same model MUST be used for both storing and querying
  (you cannot mix models — the vector spaces are incompatible)

TASK TYPES:
Gemini supports different embedding modes for different use cases.
- RETRIEVAL_DOCUMENT: use when STORING text (indexing)
- RETRIEVAL_QUERY: use when SEARCHING (querying)
This asymmetry improves retrieval accuracy significantly.
"""

import logging
import hashlib
from typing import Any
import google.generativeai as genai
from app.core.config import settings
from app.core.exceptions import EmbeddingError

logger = logging.getLogger(__name__)


class EmbeddingService:
    """
    Generates embeddings using Gemini text-embedding-004.
    Singleton — one instance for the whole app.
    """

    def __init__(self) -> None:
        self._configured = False

    def _ensure_configured(self) -> None:
        """Configure Gemini API key on first use."""
        if not self._configured:
            api_key = settings.GEMINI_API_KEY.strip()
            if not api_key or api_key == "your-gemini-api-key-here":
                raise EmbeddingError(
                    "GEMINI_API_KEY not set in .env file. "
                    "Get one from https://aistudio.google.com/app/apikey"
                )
            genai.configure(api_key=api_key)
            self._configured = True

    async def embed_text(
        self,
        text: str,
        task_type: str = "RETRIEVAL_DOCUMENT",
    ) -> list[float]:
        """
        Generate a single embedding vector for a text string.

        Args:
            text: The text to embed
            task_type: RETRIEVAL_DOCUMENT (storing) or RETRIEVAL_QUERY (searching)

        Returns:
            List of 768 floats representing the text meaning
        """
        self._ensure_configured()

        if not text or not text.strip():
            raise EmbeddingError("Cannot embed empty text")

        try:
            result = genai.embed_content(
                model=settings.GEMINI_EMBEDDING_MODEL,
                content=text.strip(),
                task_type=task_type,
            )
            embedding = result["embedding"]
            logger.debug(f"Embedded text ({len(text)} chars) -> {len(embedding)}d vector")
            return embedding

        except Exception as e:
            logger.error(f"Embedding failed: {e}")
            raise EmbeddingError(f"Gemini embedding failed: {e}") from e

    async def embed_query(self, query: str) -> list[float]:
        """
        Embed a search query (uses RETRIEVAL_QUERY task type).
        Use this when you are SEARCHING, not when storing.
        """
        return await self.embed_text(query, task_type="RETRIEVAL_QUERY")

    async def embed_document(self, text: str) -> list[float]:
        """
        Embed a document for storage (uses RETRIEVAL_DOCUMENT task type).
        Use this when you are STORING, not when searching.
        """
        return await self.embed_text(text, task_type="RETRIEVAL_DOCUMENT")

    async def embed_batch(
        self,
        texts: list[str],
        task_type: str = "RETRIEVAL_DOCUMENT",
        batch_size: int = 20,
    ) -> list[list[float]]:
        """
        Embed multiple texts efficiently.

        Processes in batches to avoid rate limits.
        Gemini has a requests-per-minute limit so we batch
        and add small delays between batches.

        Args:
            texts: List of texts to embed
            task_type: Embedding task type
            batch_size: How many to process per batch (default 20)

        Returns:
            List of embedding vectors in same order as input texts
        """
        self._ensure_configured()

        if not texts:
            return []

        import asyncio
        all_embeddings = []

        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            batch_embeddings = []

            for text in batch:
                if text and text.strip():
                    embedding = await self.embed_text(text, task_type)
                    batch_embeddings.append(embedding)
                else:
                    # Empty text — return zero vector as placeholder
                    batch_embeddings.append([0.0] * settings.EMBEDDING_DIMENSIONS)

            all_embeddings.extend(batch_embeddings)

            # Rate limit protection — pause between batches
            if i + batch_size < len(texts):
                await asyncio.sleep(0.5)

            logger.debug(f"Embedded batch {i//batch_size + 1}: {len(batch)} texts")

        return all_embeddings

    @staticmethod
    def text_to_point_id(text_id: str) -> str:
        """
        Convert a string ID (like "CVE-2021-44228") to a
        stable UUID-format string for Qdrant point IDs.

        Qdrant requires point IDs to be either integers or UUID strings.
        We hash the original ID to get a stable UUID.
        """
        hash_hex = hashlib.md5(text_id.encode()).hexdigest()
        return f"{hash_hex[:8]}-{hash_hex[8:12]}-{hash_hex[12:16]}-{hash_hex[16:20]}-{hash_hex[20:32]}"


# Singleton
embedding_service = EmbeddingService()
