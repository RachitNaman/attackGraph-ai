"""
agents/attack_path_agent.py
=============================
The Attack Path Explanation Agent — LangGraph StateGraph definition.

WHAT IS A LANGGRAPH STATEGRAPH?
Think of it as a flowchart you can execute.
  - Nodes = steps in the pipeline (functions)
  - Edges = connections between steps
  - Conditional edges = "go to node X if condition Y, else go to node Z"
  - State = data passed between nodes (the baton in a relay race)

THE AGENT PIPELINE:
  [START]
      |
      v
  [query_understanding]     <- Gemini parses intent
      |
      v
  [graph_traversal]         <- Neo4j finds attack paths
      |
      v
  [context_enrichment]      <- Qdrant adds semantic context
      |
      v
  [path_scoring]            <- Pure Python scores each path
      |
      v
  [explanation_generation]  <- Gemini generates the narrative
      |
      v
  [END]

CONDITIONAL ROUTING:
  After query_understanding, if confidence is too low,
  we skip straight to a simplified analysis rather than
  running a full traversal on a misunderstood query.

MULTI-AGENT EVOLUTION PLAN:
  This agent is the FIRST of three planned agents:

  AttackPathAgent (this file)
    -> Finds and explains how attacks happen
    -> Output: attack narrative + risk assessment

  DefenseAgent (future)
    -> Receives AttackPathAgent output
    -> Generates network hardening recommendations
    -> Simulates "what if we patched X?" scenarios

  RiskAnalysisAgent (future)
    -> Aggregates results from both agents
    -> Produces CVSS-weighted organizational risk score
    -> Generates executive dashboard data

  The agents communicate via the shared state fields:
  attack_paths, risk_level, recommendations are the handoff interface.
"""

import logging
from langgraph.graph import StateGraph, START, END

from app.agents.state import AttackPathAgentState, create_initial_state
from app.agents.nodes.query_understanding import query_understanding_node
from app.agents.nodes.graph_traversal import graph_traversal_node
from app.agents.nodes.context_enrichment import context_enrichment_node
from app.agents.nodes.path_scoring import path_scoring_node
from app.agents.nodes.explanation_generation import explanation_generation_node

logger = logging.getLogger(__name__)


def should_run_full_analysis(state: AttackPathAgentState) -> str:
    """
    Conditional edge function after query_understanding.

    LangGraph calls this to decide which node to go to next.
    Returns the NAME of the next node as a string.

    If confidence is very low, we still run the full pipeline
    but the graph traversal will use default settings.
    """
    confidence = state.get("confidence", 0.5)
    error = state.get("error")

    if error and "fatal" in str(error).lower():
        logger.warning(f"Fatal error detected, routing to END: {error}")
        return "end"

    # Always run full analysis — we have enough context
    return "graph_traversal"


def build_attack_path_agent() -> StateGraph:
    """
    Construct and compile the LangGraph StateGraph.

    This function is called ONCE at application startup.
    The compiled graph is stored as a singleton and reused
    for every analysis request — much more efficient than
    rebuilding the graph on every request.

    Returns:
        Compiled LangGraph app ready to invoke
    """
    # Create the state graph with our state schema
    graph = StateGraph(AttackPathAgentState)

    # ── Add nodes ──────────────────────────────────────────────────────────
    # Each node is an async function that receives and returns state
    graph.add_node("query_understanding",    query_understanding_node)
    graph.add_node("graph_traversal",        graph_traversal_node)
    graph.add_node("context_enrichment",     context_enrichment_node)
    graph.add_node("path_scoring",           path_scoring_node)
    graph.add_node("explanation_generation", explanation_generation_node)

    # ── Add edges ──────────────────────────────────────────────────────────
    # START -> first node
    graph.add_edge(START, "query_understanding")

    # Conditional edge after query understanding
    graph.add_conditional_edges(
        "query_understanding",
        should_run_full_analysis,
        {
            "graph_traversal": "graph_traversal",
            "end": END,
        }
    )

    # Linear flow for the rest of the pipeline
    graph.add_edge("graph_traversal",        "context_enrichment")
    graph.add_edge("context_enrichment",     "path_scoring")
    graph.add_edge("path_scoring",           "explanation_generation")
    graph.add_edge("explanation_generation", END)

    # Compile the graph into an executable app
    compiled = graph.compile()
    logger.info("Attack path agent compiled successfully")
    return compiled


# Build and cache the agent at module load time
# This happens once when FastAPI starts — all requests reuse this instance
attack_path_agent = build_attack_path_agent()


async def run_attack_path_analysis(
    query: str,
    session_id: str,
    max_hops: int = 8,
    source_id: str | None = None,
    target_id: str | None = None,
) -> AttackPathAgentState:
    """
    Public interface for running the attack path analysis agent.

    This is what the API endpoint calls.
    It creates the initial state, runs the full agent pipeline,
    and returns the final state with all results populated.

    Args:
        query: User's natural language question
        session_id: Unique ID for this analysis run
        max_hops: Maximum graph traversal depth
        source_id: Optional specific source node to start from
        target_id: Optional specific target node to analyze

    Returns:
        Final AttackPathAgentState with all fields populated
    """
    logger.info(f"Starting attack path analysis: session={session_id}")

    initial_state = create_initial_state(
        query=query,
        session_id=session_id,
        max_hops=max_hops,
        source_id=source_id,
        target_id=target_id,
    )

    # Run the agent — LangGraph executes all nodes in order
    # ainvoke() is the async version — required for FastAPI
    final_state = await attack_path_agent.ainvoke(initial_state)

    logger.info(
        f"Analysis complete: session={session_id} "
        f"risk={final_state.get('risk_level')} "
        f"paths={final_state.get('total_paths_found', 0)}"
    )

    return final_state
