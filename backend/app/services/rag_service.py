"""
services/rag_service.py
========================
RAG (Retrieval Augmented Generation) service.

Handles all Qdrant operations at the business logic level:
- Storing CVEs, assets, threat intel as searchable vectors
- Retrieving semantically relevant context for any query

This is one half of Graph RAG.
The other half is graph_service.py (structural context from Neo4j).
graphrag_service.py fuses them both together.

WHAT THIS SERVICE DOES:
  embed text -> store in Qdrant -> search by meaning -> return context

WHAT THIS SERVICE DOES NOT DO:
  Neo4j queries, LLM calls, HTTP handling
"""

import logging
from qdrant_client.models import PointStruct

from app.vectorstore.qdrant_client import qdrant_manager
from app.vectorstore.embeddings import embedding_service
from app.vectorstore.collections import (
    CVE_COLLECTION,
    ASSETS_COLLECTION,
    THREAT_INTEL_COLLECTION,
)
from app.core.exceptions import VectorStoreError, EmbeddingError

logger = logging.getLogger(__name__)


class RAGService:
    """
    Vector store service — store and retrieve semantic context.
    All methods are async. Read and write operations both supported.
    """

    # =======================================================================
    # CVE OPERATIONS
    # =======================================================================

    async def store_cve(
        self,
        cve_id: str,
        description: str,
        cvss_score: float,
        severity: str,
        affected_component: str = "",
        cwe_id: str = "",
        is_exploitable: bool = False,
        has_public_exploit: bool = False,
        exploit_maturity: str = "unproven",
        published_date: str = "",
    ) -> str:
        """
        Embed and store a CVE in Qdrant.

        The text we embed combines multiple fields into one rich
        semantic document so the search captures all aspects:
        description + component + severity context.

        Returns the Qdrant point ID.
        """
        # Build rich text for embedding
        # More context = better semantic search results
        embed_text = f"""
        CVE ID: {cve_id}
        Description: {description}
        Affected Component: {affected_component}
        Severity: {severity} (CVSS: {cvss_score})
        CWE: {cwe_id}
        Exploitable: {is_exploitable}
        Public Exploit Available: {has_public_exploit}
        Exploit Maturity: {exploit_maturity}
        """.strip()

        vector = await embedding_service.embed_document(embed_text)
        point_id = embedding_service.text_to_point_id(cve_id)

        await qdrant_manager.upsert_points(
            CVE_COLLECTION,
            [PointStruct(
                id=point_id,
                vector=vector,
                payload={
                    "cve_id": cve_id,
                    "description": description,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "affected_component": affected_component,
                    "cwe_id": cwe_id,
                    "is_exploitable": is_exploitable,
                    "has_public_exploit": has_public_exploit,
                    "exploit_maturity": exploit_maturity,
                    "published_date": published_date,
                }
            )]
        )

        logger.info(f"Stored CVE in Qdrant: {cve_id}")
        return point_id

    async def search_cves(
        self,
        query: str,
        top_k: int = 5,
        severity_filter: str | None = None,
        exploitable_only: bool = False,
    ) -> list[dict]:
        """
        Search CVEs by semantic similarity to a query.

        Examples:
            search_cves("remote code execution in web server")
            search_cves("privilege escalation linux", exploitable_only=True)
            search_cves("authentication bypass", severity_filter="CRITICAL")

        Args:
            query: Natural language search query
            top_k: Number of results
            severity_filter: "CRITICAL", "HIGH", "MEDIUM", "LOW" or None
            exploitable_only: Only return actively exploitable CVEs
        """
        query_vector = await embedding_service.embed_query(query)

        filters = {}
        if severity_filter:
            filters["severity"] = severity_filter
        if exploitable_only:
            filters["is_exploitable"] = True

        results = await qdrant_manager.search(
            collection_name=CVE_COLLECTION,
            query_vector=query_vector,
            top_k=top_k,
            score_threshold=0.5,
            filters=filters if filters else None,
        )

        logger.debug(f"CVE search '{query[:50]}': {len(results)} results")
        return results

    async def get_cves_by_ids(self, cve_ids: list[str]) -> list[dict]:
        """
        Retrieve specific CVEs by their IDs from Qdrant.

        Called after graph traversal finds CVE IDs on attack paths.
        This is the bridge between Neo4j structural data and
        Qdrant semantic data — graph gives us IDs, Qdrant gives us context.

        Args:
            cve_ids: List of CVE IDs found by graph traversal (e.g. ["CVE-2021-44228"])

        Returns:
            List of CVE payloads with full descriptions and metadata
        """
        results = []
        for cve_id in cve_ids:
            point_id = embedding_service.text_to_point_id(cve_id)
            point = await qdrant_manager.get_point(CVE_COLLECTION, point_id)
            if point:
                results.append(point["payload"])
            else:
                # CVE not in Qdrant yet — return minimal info
                results.append({"cve_id": cve_id, "description": "Not yet indexed"})

        return results

    async def store_cves_batch(self, cves: list[dict]) -> int:
        """
        Batch store multiple CVEs efficiently.
        Used during initial data ingestion.

        Args:
            cves: List of CVE dicts with keys matching store_cve() params

        Returns:
            Number of CVEs stored
        """
        if not cves:
            return 0

        texts = []
        for cve in cves:
            text = f"""
            CVE ID: {cve.get('cve_id', '')}
            Description: {cve.get('description', '')}
            Affected Component: {cve.get('affected_component', '')}
            Severity: {cve.get('severity', '')} (CVSS: {cve.get('cvss_score', 0)})
            Exploitable: {cve.get('is_exploitable', False)}
            """.strip()
            texts.append(text)

        vectors = await embedding_service.embed_batch(texts)

        points = [
            PointStruct(
                id=embedding_service.text_to_point_id(cve.get("cve_id", f"cve-{i}")),
                vector=vectors[i],
                payload=cve,
            )
            for i, cve in enumerate(cves)
        ]

        await qdrant_manager.upsert_points(CVE_COLLECTION, points)
        logger.info(f"Batch stored {len(points)} CVEs in Qdrant")
        return len(points)

    # =======================================================================
    # ASSET METADATA OPERATIONS
    # =======================================================================

    async def store_asset_metadata(
        self,
        asset_id: str,
        name: str,
        asset_type: str,
        description: str,
        notes: str = "",
        known_issues: str = "",
        tags: list[str] | None = None,
    ) -> str:
        """
        Store semantic metadata about an asset.

        This captures the QUALITATIVE aspects of an asset that
        Neo4j cannot store meaningfully — narrative descriptions,
        analyst notes, known operational issues.
        """
        embed_text = f"""
        Asset: {name}
        Type: {asset_type}
        Description: {description}
        Notes: {notes}
        Known Issues: {known_issues}
        Tags: {', '.join(tags or [])}
        """.strip()

        vector = await embedding_service.embed_document(embed_text)
        point_id = embedding_service.text_to_point_id(asset_id)

        await qdrant_manager.upsert_points(
            ASSETS_COLLECTION,
            [PointStruct(
                id=point_id,
                vector=vector,
                payload={
                    "asset_id": asset_id,
                    "name": name,
                    "asset_type": asset_type,
                    "description": description,
                    "notes": notes,
                    "known_issues": known_issues,
                    "tags": tags or [],
                }
            )]
        )

        logger.info(f"Stored asset metadata in Qdrant: {asset_id}")
        return point_id

    async def search_assets(self, query: str, top_k: int = 5) -> list[dict]:
        """Search assets by semantic similarity."""
        query_vector = await embedding_service.embed_query(query)
        return await qdrant_manager.search(
            collection_name=ASSETS_COLLECTION,
            query_vector=query_vector,
            top_k=top_k,
            score_threshold=0.4,
        )

    # =======================================================================
    # THREAT INTELLIGENCE OPERATIONS
    # =======================================================================

    async def store_threat_intel(
        self,
        intel_id: str,
        title: str,
        content: str,
        source: str = "",
        threat_actor: str = "",
        techniques: list[str] | None = None,
        severity: str = "MEDIUM",
    ) -> str:
        """
        Store threat intelligence — MITRE ATT&CK, threat actor TTPs, IOCs.

        This gives Gemini context like:
        "APT29 is known to use this vulnerability for initial access"
        which makes the AI narrative far more actionable.
        """
        embed_text = f"""
        Title: {title}
        Threat Actor: {threat_actor}
        Content: {content}
        Techniques: {', '.join(techniques or [])}
        Source: {source}
        Severity: {severity}
        """.strip()

        vector = await embedding_service.embed_document(embed_text)
        point_id = embedding_service.text_to_point_id(intel_id)

        await qdrant_manager.upsert_points(
            THREAT_INTEL_COLLECTION,
            [PointStruct(
                id=point_id,
                vector=vector,
                payload={
                    "intel_id": intel_id,
                    "title": title,
                    "content": content,
                    "source": source,
                    "threat_actor": threat_actor,
                    "techniques": techniques or [],
                    "severity": severity,
                }
            )]
        )

        logger.info(f"Stored threat intel: {intel_id}")
        return point_id

    async def search_threat_intel(
        self,
        query: str,
        top_k: int = 3,
        threat_actor: str | None = None,
    ) -> list[dict]:
        """
        Search threat intelligence semantically.

        Args:
            query: Natural language query about attack techniques or actors
            top_k: Number of results
            threat_actor: Optional filter by specific threat actor name
        """
        query_vector = await embedding_service.embed_query(query)

        filters = {}
        if threat_actor:
            filters["threat_actor"] = threat_actor

        return await qdrant_manager.search(
            collection_name=THREAT_INTEL_COLLECTION,
            query_vector=query_vector,
            top_k=top_k,
            score_threshold=0.4,
            filters=filters if filters else None,
        )


# Singleton
rag_service = RAGService()
