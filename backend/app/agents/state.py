"""
Shared LangGraph state for the attack path analysis agent.

LangGraph passes this dictionary between nodes. Each node returns a partial
update, and LangGraph merges it into the state.
"""

from typing import Any, NotRequired, TypedDict


class AttackPathAgentState(TypedDict):
    # Request context
    query: str
    session_id: str
    max_hops: int
    source_id: NotRequired[str | None]
    target_id: NotRequired[str | None]

    # Agent progress
    current_node: NotRequired[str | None]
    error: NotRequired[str | None]
    messages: NotRequired[list[dict[str, Any]]]

    # Query understanding
    parsed_intent: NotRequired[dict[str, Any]]
    query_type: NotRequired[str]
    confidence: NotRequired[float]

    # Graph traversal
    attack_paths: NotRequired[list[dict[str, Any]]]
    escalation_chains: NotRequired[list[dict[str, Any]]]
    cve_ids_on_paths: NotRequired[list[str]]
    total_paths_found: NotRequired[int]

    # Context enrichment
    cve_details: NotRequired[list[dict[str, Any]]]
    threat_intel: NotRequired[list[dict[str, Any]]]
    asset_context: NotRequired[list[dict[str, Any]]]
    fused_context_str: NotRequired[str]

    # Path scoring
    scored_paths: NotRequired[list[dict[str, Any]]]
    highest_risk_path: NotRequired[dict[str, Any] | None]
    risk_level: NotRequired[str]
    highest_cvss: NotRequired[float]
    has_public_exploit: NotRequired[bool]
    immediate_action_required: NotRequired[bool]

    # Explanation output
    executive_summary: NotRequired[str]
    explanation: NotRequired[str]
    path_summaries: NotRequired[list[str]]
    recommendations: NotRequired[list[str]]


def create_initial_state(
    query: str,
    session_id: str,
    max_hops: int = 8,
    source_id: str | None = None,
    target_id: str | None = None,
) -> AttackPathAgentState:
    """Create the initial state passed into the compiled LangGraph agent."""
    return {
        "query": query,
        "session_id": session_id,
        "max_hops": max_hops,
        "source_id": source_id,
        "target_id": target_id,
        "current_node": None,
        "error": None,
        "messages": [],
        "parsed_intent": {},
        "query_type": "general",
        "confidence": 0.0,
        "attack_paths": [],
        "escalation_chains": [],
        "cve_ids_on_paths": [],
        "total_paths_found": 0,
        "cve_details": [],
        "threat_intel": [],
        "asset_context": [],
        "fused_context_str": "",
        "scored_paths": [],
        "highest_risk_path": None,
        "risk_level": "UNKNOWN",
        "highest_cvss": 0.0,
        "has_public_exploit": False,
        "immediate_action_required": False,
        "executive_summary": "",
        "explanation": "",
        "path_summaries": [],
        "recommendations": [],
    }
