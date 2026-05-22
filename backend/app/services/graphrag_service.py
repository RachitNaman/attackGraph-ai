"""
services/graphrag_service.py
=============================
Graph RAG — the fusion layer between Neo4j and Qdrant.

This is the most important service in AttackGraph AI.
It combines STRUCTURAL intelligence (Neo4j) with
SEMANTIC intelligence (Qdrant) into a single unified
context that Gemini uses to reason about attack paths.

THE GRAPH RAG PIPELINE:

  User Query: "How can an attacker reach the database?"
       |
       v
  [1. GRAPH TRAVERSAL - Neo4j]
       Find all paths from internet-facing hosts to Database nodes.
       Result: structured path data with node IDs, relationship types,
               hop counts, CVE IDs on each path.
       |
       v
  [2. CVE ENRICHMENT - Qdrant]
       Take every CVE ID found on the paths.
       Look up rich semantic descriptions for each one.
       Result: full CVE context, similar vulnerabilities,
               threat actor usage of these CVEs.
       |
       v
  [3. ASSET CONTEXT - Qdrant]
       Semantic search for context about the assets on the path.
       Result: analyst notes, known issues, qualitative descriptions.
       |
       v
  [4. THREAT INTEL - Qdrant]
       Search for threat intelligence matching the attack pattern.
       Result: known TTPs, threat actor profiles, historical attacks.
       |
       v
  [5. CONTEXT FUSION]
       Combine all four sources into one structured context object.
       This is what gets sent to Gemini for final reasoning.
       |
       v
  [6. GEMINI REASONING]
       Gemini synthesizes everything into:
       - Human-readable attack narrative
       - Risk assessment
       - Prioritized recommendations

WHY THIS ORDER MATTERS:
  Graph traversal MUST come first — it gives you the exact CVE IDs
  and asset IDs to look up. Without it, Qdrant searches are blind.
  With it, every Qdrant search is precisely targeted at what matters.
"""

import logging
from dataclasses import dataclass, field
from app.services.graph_service import GraphService, graph_service
from app.services.traversal_service import TraversalService, traversal_service
from app.services.rag_service import RAGService, rag_service
from app.core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class FusedContext:
    """
    The unified context object produced by Graph RAG.

    This is everything Gemini needs to reason about an attack scenario.
    It contains both structural (graph) and semantic (vector) intelligence.

    The LangGraph agents receive this as input to their reasoning nodes.
    """
    # Original query
    query: str = ""

    # --- Structural context from Neo4j ---
    attack_paths: list[dict] = field(default_factory=list)
    reachable_nodes: list[dict] = field(default_factory=list)
    blast_radius: dict = field(default_factory=dict)
    escalation_chains: list[dict] = field(default_factory=list)

    # --- Semantic context from Qdrant ---
    cve_details: list[dict] = field(default_factory=list)
    similar_cves: list[dict] = field(default_factory=list)
    asset_context: list[dict] = field(default_factory=list)
    threat_intel: list[dict] = field(default_factory=list)

    # --- Metadata ---
    cve_ids_found: list[str] = field(default_factory=list)
    total_paths: int = 0
    highest_cvss: float = 0.0
    has_public_exploit: bool = False
    immediate_risk: bool = False

    def to_prompt_context(self) -> str:
        """
        Format the fused context as a structured string for Gemini.

        This is the context block that gets inserted into the
        Gemini prompt. Structured clearly so Gemini can parse it.
        """
        lines = [
            f"QUERY: {self.query}",
            "",
            "=== ATTACK PATHS (from graph traversal) ===",
        ]

        if self.attack_paths:
            for i, path in enumerate(self.attack_paths[:5], 1):
                nodes = path.get("path_nodes", path.get("nodes", []))
                node_names = " -> ".join(
                    n.get("name", n.get("id", "?")) for n in nodes
                )
                hops = path.get("hop_count", path.get("hops", "?"))
                lines.append(f"Path {i} ({hops} hops): {node_names}")
        else:
            lines.append("No attack paths found.")

        lines += [
            "",
            "=== CVE DETAILS (from vector search) ===",
        ]

        if self.cve_details:
            for cve in self.cve_details:
                lines.append(
                    f"- {cve.get('cve_id', 'Unknown')}: "
                    f"CVSS {cve.get('cvss_score', 'N/A')} | "
                    f"{cve.get('severity', 'N/A')} | "
                    f"{cve.get('description', 'No description')[:200]}"
                )
        else:
            lines.append("No CVE details available.")

        lines += [
            "",
            "=== THREAT INTELLIGENCE ===",
        ]

        if self.threat_intel:
            for intel in self.threat_intel[:3]:
                payload = intel.get("payload", intel)
                lines.append(
                    f"- {payload.get('title', 'Unknown')}: "
                    f"{payload.get('content', '')[:200]}"
                )
        else:
            lines.append("No relevant threat intelligence found.")

        lines += [
            "",
            "=== RISK SUMMARY ===",
            f"Total attack paths found: {self.total_paths}",
            f"Highest CVSS score on paths: {self.highest_cvss}",
            f"Public exploit available: {self.has_public_exploit}",
            f"Immediate action required: {self.immediate_risk}",
        ]

        return "\n".join(lines)


class GraphRAGService:
    """
    The Graph RAG orchestrator.

    Coordinates Neo4j graph traversal + Qdrant semantic search
    into unified context for Gemini reasoning.

    This service is called by:
    - LangGraph agent nodes (agents/nodes/)
    - Analysis API endpoint (api/v1/analysis.py) — to be built next
    """

    def __init__(
        self,
        graph_svc: GraphService,
        traversal_svc: TraversalService,
        rag_svc: RAGService,
    ) -> None:
        self.graph = graph_svc
        self.traversal = traversal_svc
        self.rag = rag_svc

    # =======================================================================
    # MAIN GRAPH RAG PIPELINE
    # =======================================================================

    async def build_attack_context(
        self,
        query: str,
        source_id: str | None = None,
        target_id: str | None = None,
        max_hops: int = 8,
    ) -> FusedContext:
        """
        Full Graph RAG pipeline for attack path analysis.

        This is the method LangGraph agents call when they need
        complete context to reason about an attack scenario.

        Args:
            query: User's natural language question
            source_id: Optional specific source node
            target_id: Optional specific target node
            max_hops: Maximum traversal depth

        Returns:
            FusedContext with all structural + semantic intelligence
        """
        logger.info(f"Building Graph RAG context for: '{query[:80]}'")
        context = FusedContext(query=query)

        # -------------------------------------------------------------------
        # STEP 1: GRAPH TRAVERSAL
        # Get structural attack paths from Neo4j first
        # This anchors everything that follows
        # -------------------------------------------------------------------
        logger.debug("Step 1: Graph traversal")

        try:
            paths = await self.graph.find_paths_to_database(
                max_hops=max_hops,
                limit=settings.MAX_PATHS_RETURNED,
            )
            context.attack_paths = paths
            context.total_paths = len(paths)

            # Extract all CVE IDs from paths for Qdrant lookup
            cve_ids = set()
            for path in paths:
                for cve_id in path.get("cve_ids_on_path", []):
                    if cve_id:
                        cve_ids.add(cve_id)
            context.cve_ids_found = list(cve_ids)

            logger.debug(f"Found {len(paths)} paths, {len(cve_ids)} CVEs")

        except Exception as e:
            logger.warning(f"Graph traversal partial failure: {e}")

        # -------------------------------------------------------------------
        # STEP 2: ESCALATION CHAINS
        # Find privilege escalation paths
        # -------------------------------------------------------------------
        logger.debug("Step 2: Escalation chains")

        try:
            escalation = await self.traversal.find_escalation_to_root(
                max_hops=max_hops,
                limit=5,
            )
            context.escalation_chains = [
                e.__dict__ if hasattr(e, "__dict__") else e
                for e in escalation.entries
            ]

            # Check for immediate risk
            context.immediate_risk = escalation.immediate_action_required

        except Exception as e:
            logger.warning(f"Escalation chain lookup partial failure: {e}")

        # -------------------------------------------------------------------
        # STEP 3: CVE ENRICHMENT FROM QDRANT
        # Use the CVE IDs from graph traversal to fetch semantic details
        # This is the key Graph RAG integration point —
        # graph gives IDs, vector store gives meaning
        # -------------------------------------------------------------------
        logger.debug("Step 3: CVE enrichment from Qdrant")

        try:
            if context.cve_ids_found:
                # Direct lookup by ID for CVEs we know about
                cve_details = await self.rag.get_cves_by_ids(context.cve_ids_found)
                context.cve_details = cve_details

                # Also semantic search for similar CVEs
                if cve_details:
                    first_desc = cve_details[0].get("description", "")
                    if first_desc and first_desc != "Not yet indexed":
                        similar = await self.rag.search_cves(
                            query=first_desc[:200],
                            top_k=3,
                        )
                        context.similar_cves = similar

                # Compute risk metrics
                cvss_scores = [
                    c.get("cvss_score", 0.0)
                    for c in cve_details
                    if c.get("cvss_score")
                ]
                context.highest_cvss = max(cvss_scores, default=0.0)
                context.has_public_exploit = any(
                    c.get("has_public_exploit", False) for c in cve_details
                )

            else:
                # No specific CVEs from graph — do semantic search
                cve_results = await self.rag.search_cves(
                    query=query,
                    top_k=5,
                )
                context.cve_details = [r["payload"] for r in cve_results]

        except Exception as e:
            logger.warning(f"CVE enrichment partial failure: {e}")

        # -------------------------------------------------------------------
        # STEP 4: ASSET CONTEXT FROM QDRANT
        # Get qualitative descriptions of assets on the attack paths
        # -------------------------------------------------------------------
        logger.debug("Step 4: Asset context from Qdrant")

        try:
            asset_results = await self.rag.search_assets(
                query=query,
                top_k=3,
            )
            context.asset_context = asset_results

        except Exception as e:
            logger.warning(f"Asset context lookup partial failure: {e}")

        # -------------------------------------------------------------------
        # STEP 5: THREAT INTELLIGENCE FROM QDRANT
        # Find relevant threat intel matching the attack pattern
        # -------------------------------------------------------------------
        logger.debug("Step 5: Threat intelligence from Qdrant")

        try:
            threat_results = await self.rag.search_threat_intel(
                query=query,
                top_k=3,
            )
            context.threat_intel = threat_results

        except Exception as e:
            logger.warning(f"Threat intel lookup partial failure: {e}")

        logger.info(
            f"Graph RAG context built: "
            f"{context.total_paths} paths, "
            f"{len(context.cve_details)} CVEs, "
            f"{len(context.threat_intel)} intel items"
        )

        return context

    async def enrich_path_with_context(
        self,
        path: dict,
    ) -> dict:
        """
        Enrich a single attack path with semantic CVE context.

        Called when you have one specific path and want to add
        full CVE descriptions and threat intel to it.

        Args:
            path: A single attack path dict from graph traversal

        Returns:
            The same path dict with added 'cve_context' and 'threat_intel' keys
        """
        enriched = dict(path)

        cve_ids = path.get("cve_ids_on_path", [])
        if cve_ids:
            cve_details = await self.rag.get_cves_by_ids(cve_ids)
            enriched["cve_context"] = cve_details

            # Search for threat intel about these specific CVEs
            cve_query = " ".join(cve_ids)
            intel = await self.rag.search_threat_intel(query=cve_query, top_k=2)
            enriched["threat_intel"] = intel

        return enriched

    async def semantic_attack_search(
        self,
        query: str,
        top_k: int = 5,
    ) -> dict:
        """
        Pure semantic search across all collections.

        Used when the user asks a general question with no
        specific source/target in mind.

        Example: "What are the most dangerous vulnerabilities
                  in web servers running nginx?"

        Returns results from all three Qdrant collections
        merged and ranked by relevance.
        """
        cve_results = await self.rag.search_cves(query=query, top_k=top_k)
        asset_results = await self.rag.search_assets(query=query, top_k=3)
        intel_results = await self.rag.search_threat_intel(query=query, top_k=3)

        return {
            "query": query,
            "cves": cve_results,
            "assets": asset_results,
            "threat_intel": intel_results,
            "total_results": len(cve_results) + len(asset_results) + len(intel_results),
        }


# Singleton — inject dependencies at module level
graphrag_service = GraphRAGService(
    graph_svc=graph_service,
    traversal_svc=traversal_service,
    rag_svc=rag_service,
)
