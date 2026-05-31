"""
agents/nodes/context_enrichment.py
=====================================
LangGraph Node 3: Enrich attack paths with semantic context from Qdrant.

WHAT THIS NODE DOES:
  Receives: state with cve_ids_on_paths from graph traversal
  Calls: RAGService (Qdrant) for CVE details + threat intel
  Returns: cve_details, threat_intel, asset_context, fused_context_str

THIS IS THE GRAPH RAG INTEGRATION POINT:
  Node 2 (graph traversal) gave us CVE IDs from Neo4j.
  This node uses those EXACT IDs to fetch rich descriptions from Qdrant.
  Without Node 2, this search would be blind.
  With Node 2, every Qdrant search is precisely targeted.

The fused_context_str output is what gets sent to Gemini in Node 5.
"""

import logging
from app.agents.state import AttackPathAgentState
from app.services.graphrag_service import graphrag_service

logger = logging.getLogger(__name__)


async def context_enrichment_node(
    state: AttackPathAgentState,
) -> AttackPathAgentState:
    """
    LangGraph node: fetch semantic context from Qdrant for graph results.
    """
    logger.info(
        f"[context_enrichment] "
        f"enriching {len(state.get('cve_ids_on_paths') or [])} CVEs"
    )

    try:
        # Build full fused context using GraphRAG service
        fused = await graphrag_service.build_attack_context(
            query=state["query"],
            max_hops=state.get("max_hops", 8),
        )

        logger.info(
            f"[context_enrichment] "
            f"cve_details={len(fused.cve_details)} "
            f"threat_intel={len(fused.threat_intel)} "
            f"asset_context={len(fused.asset_context)}"
        )

        return {
            "cve_details": fused.cve_details,
            "threat_intel": fused.threat_intel,
            "asset_context": fused.asset_context,
            "fused_context_str": fused.to_prompt_context(),
            "current_node": "context_enrichment",
            "error": None,
        }

    except Exception as e:
        logger.error(f"[context_enrichment] Failed: {e}")
        # Non-fatal — we can still explain paths without semantic context
        return {
            "cve_details": [],
            "threat_intel": [],
            "asset_context": [],
            "fused_context_str": f"QUERY: {state['query']}\nContext enrichment unavailable.",
            "current_node": "context_enrichment",
            "error": None,  # Don't block pipeline for enrichment failure
        }
