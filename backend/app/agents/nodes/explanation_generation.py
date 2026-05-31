"""
agents/nodes/explanation_generation.py
========================================
LangGraph Node 5: Generate AI explanation using Gemini.

WHAT THIS NODE DOES:
  Receives: fused_context_str, scored_paths, risk_level from previous nodes
  Calls: GeminiService.explain_attack_paths() (LLM call)
  Returns: explanation, path_summaries, recommendations, executive_summary

THIS IS WHERE GEMINI EARNS ITS PLACE:
  All previous nodes did deterministic work:
  - Neo4j found paths (graph algorithm)
  - Qdrant found CVE context (vector similarity)
  - Python scored paths (math)

  Now we have ALL the data. Gemini's job is to:
  1. Read the fused context (graph paths + CVE details + threat intel)
  2. Write a coherent attack narrative a human can understand
  3. Generate specific, prioritized recommendations
  4. Produce an executive summary for non-technical leadership

  This is judgment + language — exactly what LLMs excel at.
  Everything before this node was deliberately LLM-free.
"""

import logging
from app.agents.state import AttackPathAgentState
from app.services.gemini_service import gemini_service

logger = logging.getLogger(__name__)


async def explanation_generation_node(
    state: AttackPathAgentState,
) -> AttackPathAgentState:
    """
    LangGraph node: generate AI-powered attack path explanation.
    The final and most important node in the pipeline.
    """
    logger.info(
        f"[explanation_generation] "
        f"risk={state.get('risk_level')} "
        f"paths={state.get('total_paths_found', 0)}"
    )

    fused_context = state.get("fused_context_str") or ""

    # Enhance context with scoring results for richer Gemini input
    scored_paths = state.get("scored_paths") or []
    if scored_paths:
        path_section = "\n=== SCORED ATTACK PATHS ===\n"
        for i, path in enumerate(scored_paths[:5], 1):
            nodes = path.get("path_nodes", path.get("nodes", []))
            node_names = " -> ".join(
                n.get("name", n.get("id", "?")) for n in nodes
            )
            path_section += (
                f"Path {i} (risk score: {path.get('risk_score', 0):.1f}): "
                f"{node_names}\n"
            )
        fused_context = fused_context + path_section

    # Add risk summary
    fused_context += f"\n=== RISK ASSESSMENT ===\n"
    fused_context += f"Overall Risk Level: {state.get('risk_level', 'UNKNOWN')}\n"
    fused_context += f"Highest CVSS: {state.get('highest_cvss', 0)}\n"
    fused_context += f"Public Exploit Available: {state.get('has_public_exploit', False)}\n"
    fused_context += f"Immediate Action Required: {state.get('immediate_action_required', False)}\n"
    fused_context += f"Escalation Chains Found: {len(state.get('escalation_chains') or [])}\n"

    try:
        result = await gemini_service.explain_attack_paths(fused_context)

        # Extract fields from Gemini's JSON response
        explanation = result.get("technical_narrative", "")
        executive_summary = result.get("executive_summary", "")
        path_summaries = result.get("path_summaries", [])
        raw_recs = result.get("recommendations", [])

        # Normalize recommendations to strings
        recommendations = []
        for rec in raw_recs:
            if isinstance(rec, dict):
                priority = rec.get("priority", "")
                action = rec.get("action", "")
                impact = rec.get("impact", "")
                effort = rec.get("effort", "")
                recommendations.append(
                    f"[P{priority}] {action} "
                    f"(Impact: {impact}, Effort: {effort})"
                )
            elif isinstance(rec, str):
                recommendations.append(rec)

        logger.info(
            f"[explanation_generation] "
            f"explanation={len(explanation)} chars "
            f"recommendations={len(recommendations)}"
        )

        return {
            "explanation": explanation,
            "executive_summary": executive_summary,
            "path_summaries": path_summaries,
            "recommendations": recommendations,
            "current_node": "explanation_generation",
            "error": None,
            "messages": [{
                "role": "assistant",
                "content": explanation,
                "type": "attack_explanation",
            }],
        }

    except Exception as e:
        logger.error(f"[explanation_generation] Gemini failed: {e}")

        # Graceful fallback — return structured data without AI narrative
        fallback_explanation = _build_fallback_explanation(state)

        return {
            "explanation": fallback_explanation,
            "executive_summary": (
                f"Security analysis found {state.get('total_paths_found', 0)} "
                f"attack paths with {state.get('risk_level', 'UNKNOWN')} risk. "
                f"AI narrative generation failed — see raw path data."
            ),
            "path_summaries": [],
            "recommendations": [
                "Review attack paths manually in the graph visualization",
                "Check CVE details for vulnerabilities on each path",
            ],
            "current_node": "explanation_generation",
            "error": f"AI explanation failed: {e}",
            "messages": [],
        }


def _build_fallback_explanation(state: AttackPathAgentState) -> str:
    """
    Build a basic explanation from raw data when Gemini fails.
    Ensures the agent always returns something useful.
    """
    lines = [
        f"Attack Path Analysis for: {state.get('query', 'Unknown query')}",
        f"Risk Level: {state.get('risk_level', 'UNKNOWN')}",
        f"Total Paths Found: {state.get('total_paths_found', 0)}",
        f"Highest CVSS Score: {state.get('highest_cvss', 0)}",
        "",
        "Attack Paths:",
    ]

    scored_paths = state.get("scored_paths") or []
    for i, path in enumerate(scored_paths[:5], 1):
        nodes = path.get("path_nodes", path.get("nodes", []))
        node_names = " -> ".join(n.get("name", "?") for n in nodes)
        lines.append(f"  {i}. {node_names}")

    return "\n".join(lines)
