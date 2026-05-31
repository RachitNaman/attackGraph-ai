"""
agents/nodes/query_understanding.py
=====================================
LangGraph Node 1: Parse user query into structured intent.

WHAT THIS NODE DOES:
  Receives: raw user query string
  Calls: Gemini via GeminiService.parse_query_intent()
  Returns: updated state with parsed_intent, query_type, confidence

WHY THIS NODE EXISTS:
  Users type natural language like "how can an attacker reach the DB?"
  The graph traversal system needs structured data like:
  {query_type: "path_finding", target_type: "database"}
  This node bridges that gap using Gemini.

NODE CONTRACT:
  - Always returns state (never raises — errors go into state.error)
  - Sets state.current_node = "query_understanding"
  - On success: populates parsed_intent, query_type, confidence
  - On failure: sets state.error, leaves other fields as None
"""

import logging
from app.agents.state import AttackPathAgentState
from app.services.gemini_service import gemini_service

logger = logging.getLogger(__name__)


async def query_understanding_node(
    state: AttackPathAgentState,
) -> AttackPathAgentState:
    """
    LangGraph node: parse natural language query into structured intent.

    LangGraph calls this function with the current state dict.
    We return a PARTIAL state update — only the fields we changed.
    LangGraph merges our update into the full state automatically.
    """
    logger.info(f"[query_understanding] Processing: '{state['query'][:80]}'")

    try:
        # Call Gemini to parse the intent
        parsed = await gemini_service.parse_query_intent(state["query"])

        logger.info(
            f"[query_understanding] "
            f"type={parsed.get('query_type')} "
            f"target={parsed.get('target_type')} "
            f"confidence={parsed.get('confidence', 0):.2f}"
        )

        # Return ONLY the fields this node updates
        # LangGraph merges this with the existing state
        return {
            "parsed_intent": parsed,
            "query_type": parsed.get("query_type", "general"),
            "confidence": parsed.get("confidence", 0.5),
            "current_node": "query_understanding",
            "error": None,
        }

    except Exception as e:
        logger.error(f"[query_understanding] Failed: {e}")
        return {
            "parsed_intent": {"query_type": "general"},
            "query_type": "general",
            "confidence": 0.0,
            "current_node": "query_understanding",
            "error": f"Query understanding failed: {e}",
        }
