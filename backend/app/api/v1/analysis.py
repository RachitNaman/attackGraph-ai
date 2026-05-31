"""
api/v1/analysis.py
===================
The main AI analysis endpoint — the crown jewel of AttackGraph AI.

This endpoint:
1. Receives a natural language question
2. Runs the full LangGraph agent pipeline
3. Returns AI-generated attack path explanation + recommendations

This is where everything comes together:
  Neo4j + Qdrant + Gemini + LangChain + LangGraph
  all working in a single request.
"""

import uuid
import time
import logging
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
import json

from app.agents.attack_path_agent import run_attack_path_analysis

router = APIRouter()
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------

class AnalysisRequest(BaseModel):
    query: str = Field(
        ...,
        description="Natural language security question",
        examples=["How can an attacker reach the database?"],
    )
    session_id: str | None = Field(
        default=None,
        description="Optional session ID for tracking. Auto-generated if not provided.",
    )
    max_hops: int = Field(
        default=8,
        ge=1,
        le=10,
        description="Maximum graph traversal depth",
    )
    source_id: str | None = Field(
        default=None,
        description="Optional specific source node ID",
    )
    target_id: str | None = Field(
        default=None,
        description="Optional specific target node ID",
    )


class AnalysisResponse(BaseModel):
    session_id: str
    query: str
    risk_level: str
    executive_summary: str
    explanation: str
    path_summaries: list[str]
    recommendations: list[str]
    total_paths_found: int
    highest_cvss: float
    has_public_exploit: bool
    immediate_action_required: bool
    duration_ms: int
    error: str | None = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post(
    "/analyze",
    response_model=AnalysisResponse,
    summary="AI-powered attack path analysis",
    description="""
    The core AttackGraph AI endpoint.

    Runs the full LangGraph pipeline:
    1. **Query Understanding** — Gemini parses your question into structured intent
    2. **Graph Traversal** — Neo4j finds attack paths matching your query
    3. **Context Enrichment** — Qdrant adds CVE descriptions + threat intelligence
    4. **Path Scoring** — Python ranks paths by composite risk score
    5. **Explanation Generation** — Gemini generates the attack narrative + recommendations

    **Example queries:**
    - "How can an attacker reach the database?"
    - "What is the blast radius if the web server is compromised?"
    - "Show me all privilege escalation paths to root"
    - "Which vulnerabilities pose the most immediate risk?"
    """,
)
async def analyze_attack_paths(request: AnalysisRequest) -> AnalysisResponse:
    """Run the full AI attack path analysis pipeline."""

    session_id = request.session_id or str(uuid.uuid4())
    start_time = time.time()

    logger.info(f"Analysis request: session={session_id} query='{request.query[:80]}'")

    try:
        # Run the full LangGraph agent
        final_state = await run_attack_path_analysis(
            query=request.query,
            session_id=session_id,
            max_hops=request.max_hops,
            source_id=request.source_id,
            target_id=request.target_id,
        )

        duration_ms = int((time.time() - start_time) * 1000)

        return AnalysisResponse(
            session_id=session_id,
            query=request.query,
            risk_level=final_state.get("risk_level") or "UNKNOWN",
            executive_summary=final_state.get("executive_summary") or "",
            explanation=final_state.get("explanation") or "",
            path_summaries=final_state.get("path_summaries") or [],
            recommendations=final_state.get("recommendations") or [],
            total_paths_found=final_state.get("total_paths_found") or 0,
            highest_cvss=final_state.get("highest_cvss") or 0.0,
            has_public_exploit=final_state.get("has_public_exploit") or False,
            immediate_action_required=final_state.get("immediate_action_required") or False,
            duration_ms=duration_ms,
            error=final_state.get("error"),
        )

    except Exception as e:
        duration_ms = int((time.time() - start_time) * 1000)
        logger.error(f"Analysis failed: session={session_id} error={e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/analyze/stream",
    summary="Streaming AI attack path analysis",
    description="""
    Same as /analyze but streams the response as Server-Sent Events.
    Each agent node sends a progress update as it completes.
    Use this for the frontend to show real-time progress.
    """,
)
async def analyze_attack_paths_stream(request: AnalysisRequest):
    """Stream analysis progress as Server-Sent Events."""

    session_id = request.session_id or str(uuid.uuid4())

    async def event_stream():
        # Send session ID immediately so frontend can track
        yield f"data: {json.dumps({'type': 'session', 'session_id': session_id})}\n\n"

        try:
            # Stream progress through each node
            yield f"data: {json.dumps({'type': 'progress', 'node': 'query_understanding', 'status': 'running'})}\n\n"

            final_state = await run_attack_path_analysis(
                query=request.query,
                session_id=session_id,
                max_hops=request.max_hops,
                source_id=request.source_id,
                target_id=request.target_id,
            )

            # Stream the final result
            result = {
                "type": "complete",
                "session_id": session_id,
                "risk_level": final_state.get("risk_level"),
                "executive_summary": final_state.get("executive_summary"),
                "explanation": final_state.get("explanation"),
                "recommendations": final_state.get("recommendations"),
                "total_paths_found": final_state.get("total_paths_found"),
                "immediate_action_required": final_state.get("immediate_action_required"),
            }
            yield f"data: {json.dumps(result)}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
