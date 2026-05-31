"""
agents/nodes/graph_traversal.py
=================================
LangGraph Node 2: Traverse the graph to find attack paths.

WHAT THIS NODE DOES:
  Receives: state with parsed_intent, query_type
  Calls: GraphService and TraversalService (Neo4j)
  Returns: attack_paths, cve_ids_on_paths, escalation_chains

WHY NO LLM HERE:
  Graph traversal is pure structural computation.
  Neo4j handles it with optimized graph algorithms.
  Calling an LLM for this would be slower, more expensive,
  and less accurate than just running the Cypher query.
  The LLM's job comes AFTER we have the data.
"""

import logging
from app.agents.state import AttackPathAgentState
from app.services.graph_service import graph_service
from app.services.traversal_service import traversal_service
from app.core.config import settings

logger = logging.getLogger(__name__)


async def graph_traversal_node(
    state: AttackPathAgentState,
) -> AttackPathAgentState:
    """
    LangGraph node: execute graph traversal based on parsed intent.

    Routes to different traversal strategies based on query_type:
    - path_finding   -> find_paths_to_database()
    - blast_radius   -> find_reachable_systems()
    - escalation     -> find_escalation_to_root()
    - general        -> run all three for comprehensive context
    """
    logger.info(
        f"[graph_traversal] "
        f"query_type={state.get('query_type')} "
        f"max_hops={state.get('max_hops', 8)}"
    )

    query_type = state.get("query_type", "general")
    max_hops = state.get("max_hops", 8)
    attack_paths = []
    escalation_chains = []
    cve_ids = set()

    try:
        # Always run path-to-database traversal as primary query
        paths = await graph_service.find_paths_to_database(
            max_hops=max_hops,
            limit=settings.MAX_PATHS_RETURNED,
        )
        attack_paths = paths

        # Extract CVE IDs from all paths
        for path in paths:
            for cve_id in path.get("cve_ids_on_path", []):
                if cve_id:
                    cve_ids.add(cve_id)

        # Run escalation analysis for escalation queries or general
        if query_type in ("escalation", "general", "path_finding"):
            escalation = await traversal_service.find_escalation_to_root(
                max_hops=max_hops,
                limit=5,
            )
            escalation_chains = [
                {
                    "entry_id": e.entry_id,
                    "entry_hostname": e.entry_hostname,
                    "entry_ip": e.entry_ip,
                    "escalation_cve": e.escalation_cve,
                    "cvss_score": e.cvss_score,
                    "has_public_exploit": e.has_public_exploit,
                    "admin_username": e.admin_username,
                    "hops": e.hops,
                    "full_path": e.full_path,
                }
                for e in escalation.entries
            ]

            # Add CVEs from escalation chains too
            for chain in escalation_chains:
                if chain.get("escalation_cve"):
                    cve_ids.add(chain["escalation_cve"])

        total = len(attack_paths)
        logger.info(
            f"[graph_traversal] "
            f"paths={total} "
            f"escalation_chains={len(escalation_chains)} "
            f"unique_cves={len(cve_ids)}"
        )

        return {
            "attack_paths": attack_paths,
            "escalation_chains": escalation_chains,
            "cve_ids_on_paths": list(cve_ids),
            "total_paths_found": total,
            "current_node": "graph_traversal",
            "error": None,
        }

    except Exception as e:
        logger.error(f"[graph_traversal] Failed: {e}")
        return {
            "attack_paths": [],
            "escalation_chains": [],
            "cve_ids_on_paths": [],
            "total_paths_found": 0,
            "current_node": "graph_traversal",
            "error": f"Graph traversal failed: {e}",
        }
