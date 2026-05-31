"""
agents/nodes/path_scoring.py
==============================
LangGraph Node 4: Score and rank attack paths.

WHAT THIS NODE DOES:
  Receives: attack_paths, cve_details from previous nodes
  Calls: Pure Python scoring logic (NO LLM needed)
  Returns: scored_paths, highest_risk_path, risk_level, highest_cvss

WHY NO LLM FOR SCORING:
  Risk scoring is deterministic math — CVSS weights, hop counts,
  exploit availability. An LLM would add latency and cost with
  no improvement over a well-designed formula.
  Save the LLM calls for tasks that need judgment and language.

SCORING FORMULA:
  base_score    = max_cvss_on_path * 0.5
  exploit_bonus = has_public_exploit ? 2.0 : 0.0
  hop_penalty   = (10 - hop_count) * 0.3  (shorter = riskier)
  internet_bonus = entry_is_internet_facing ? 1.5 : 0.0
  total = base_score + exploit_bonus + hop_penalty + internet_bonus
"""

import logging
from app.agents.state import AttackPathAgentState

logger = logging.getLogger(__name__)


def _score_path(path: dict, cve_lookup: dict) -> float:
    """
    Calculate composite risk score for a single attack path.

    Args:
        path: Attack path dict from Neo4j
        cve_lookup: Dict mapping cve_id -> cve_details from Qdrant

    Returns:
        Float risk score (higher = more dangerous)
    """
    hop_count = path.get("hop_count", path.get("hops", 5))
    cve_ids = path.get("cve_ids_on_path", [])

    # Find max CVSS among CVEs on this path
    max_cvss = 0.0
    has_public_exploit = False

    for cve_id in cve_ids:
        cve = cve_lookup.get(cve_id, {})
        cvss = cve.get("cvss_score", 0.0) or 0.0
        if cvss > max_cvss:
            max_cvss = cvss
        if cve.get("has_public_exploit"):
            has_public_exploit = True

    # Score components
    base_score = max_cvss * 0.5
    exploit_bonus = 2.0 if has_public_exploit else 0.0
    hop_penalty = max(0.0, (10.0 - hop_count) * 0.3)  # Shorter = riskier

    # Check if entry node is internet-facing
    path_nodes = path.get("path_nodes", path.get("nodes", []))
    entry_node = path_nodes[0] if path_nodes else {}
    internet_bonus = 1.5 if entry_node.get("is_internet_facing") else 0.0

    total = base_score + exploit_bonus + hop_penalty + internet_bonus
    return round(total, 2)


def _determine_risk_level(highest_score: float, has_public_exploit: bool, highest_cvss: float) -> str:
    """Convert numeric score into categorical risk level."""
    if highest_cvss >= 9.0 and has_public_exploit:
        return "CRITICAL"
    elif highest_score >= 7.0 or highest_cvss >= 8.0:
        return "HIGH"
    elif highest_score >= 4.0 or highest_cvss >= 6.0:
        return "MEDIUM"
    return "LOW"


async def path_scoring_node(
    state: AttackPathAgentState,
) -> AttackPathAgentState:
    """LangGraph node: score and rank attack paths by risk."""

    attack_paths = state.get("attack_paths") or []
    cve_details = state.get("cve_details") or []

    logger.info(f"[path_scoring] Scoring {len(attack_paths)} paths")

    if not attack_paths:
        return {
            "scored_paths": [],
            "highest_risk_path": None,
            "risk_level": "LOW",
            "highest_cvss": 0.0,
            "has_public_exploit": False,
            "immediate_action_required": False,
            "current_node": "path_scoring",
        }

    # Build CVE lookup dict for fast access
    cve_lookup = {
        cve.get("cve_id", ""): cve
        for cve in cve_details
        if cve.get("cve_id")
    }

    # Score every path
    scored_paths = []
    for path in attack_paths:
        score = _score_path(path, cve_lookup)
        scored_path = {**path, "risk_score": score}
        scored_paths.append(scored_path)

    # Sort by score descending
    scored_paths.sort(key=lambda p: p["risk_score"], reverse=True)

    # Determine overall risk metrics
    highest_score = scored_paths[0]["risk_score"] if scored_paths else 0.0
    highest_cvss = max(
        (c.get("cvss_score", 0.0) or 0.0 for c in cve_details),
        default=0.0
    )
    has_public_exploit = any(
        c.get("has_public_exploit", False) for c in cve_details
    )
    risk_level = _determine_risk_level(highest_score, has_public_exploit, highest_cvss)
    immediate_action = risk_level == "CRITICAL" or (has_public_exploit and highest_cvss >= 7.0)

    logger.info(
        f"[path_scoring] "
        f"risk={risk_level} "
        f"highest_cvss={highest_cvss} "
        f"public_exploit={has_public_exploit}"
    )

    return {
        "scored_paths": scored_paths,
        "highest_risk_path": scored_paths[0] if scored_paths else None,
        "risk_level": risk_level,
        "highest_cvss": highest_cvss,
        "has_public_exploit": has_public_exploit,
        "immediate_action_required": immediate_action,
        "current_node": "path_scoring",
    }
