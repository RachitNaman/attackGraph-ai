"""
api/v1/rag.py
==============
RAG and Graph RAG API endpoints.

Endpoints:
  POST /rag/analyze          -> full Graph RAG pipeline
  GET  /rag/search/cves      -> semantic CVE search
  GET  /rag/search/assets    -> semantic asset search
  GET  /rag/search/intel     -> semantic threat intel search
  POST /rag/ingest/cve       -> store a CVE in Qdrant
  POST /rag/ingest/intel     -> store threat intel in Qdrant
"""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from app.services.rag_service import RAGService
from app.services.graphrag_service import GraphRAGService
from app.dependencies import get_rag_service, get_graphrag_service

router = APIRouter()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    query: str
    source_id: str | None = None
    target_id: str | None = None
    max_hops: int = 8


class IngestCVERequest(BaseModel):
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    affected_component: str = ""
    cwe_id: str = ""
    is_exploitable: bool = False
    has_public_exploit: bool = False
    exploit_maturity: str = "unproven"
    published_date: str = ""


class IngestIntelRequest(BaseModel):
    intel_id: str
    title: str
    content: str
    source: str = ""
    threat_actor: str = ""
    techniques: list[str] = Field(default_factory=list)  # fixed mutable default
    severity: str = "MEDIUM"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post(
    "/analyze",
    summary="Full Graph RAG attack analysis",
    description="""
    Runs the complete Graph RAG pipeline:
    1. Graph traversal (Neo4j) — finds attack paths
    2. CVE enrichment (Qdrant) — adds semantic CVE context
    3. Asset context (Qdrant) — adds qualitative asset info
    4. Threat intel (Qdrant) — adds threat actor intelligence
    5. Context fusion — returns unified context for Gemini
    """,
)
async def analyze_attack(
    request: AnalyzeRequest,
    service: GraphRAGService = Depends(get_graphrag_service),
):
    context = await service.build_attack_context(
        query=request.query,
        source_id=request.source_id,
        target_id=request.target_id,
        max_hops=request.max_hops,
    )
    return {
        "query": context.query,
        "total_paths": context.total_paths,
        "cve_ids_found": context.cve_ids_found,
        "highest_cvss": context.highest_cvss,
        "has_public_exploit": context.has_public_exploit,
        "immediate_risk": context.immediate_risk,
        "attack_paths": context.attack_paths[:5],
        "cve_details": context.cve_details,
        "threat_intel": context.threat_intel,
        "prompt_context": context.to_prompt_context(),
    }


@router.get(
    "/search/cves",
    summary="Semantic CVE search",
    description="Search CVEs by natural language using vector similarity.",
)
async def search_cves(
    query: str = Query(..., description="Natural language search query"),
    top_k: int = Query(default=5, ge=1, le=20),
    severity: str | None = Query(default=None, description="CRITICAL, HIGH, MEDIUM, LOW"),
    exploitable_only: bool = Query(default=False),
    service: RAGService = Depends(get_rag_service),
):
    return await service.search_cves(
        query=query,
        top_k=top_k,
        severity_filter=severity,
        exploitable_only=exploitable_only,
    )


@router.get("/search/assets", summary="Semantic asset search")
async def search_assets(
    query: str = Query(..., description="Natural language search query"),
    top_k: int = Query(default=5, ge=1, le=20),
    service: RAGService = Depends(get_rag_service),
):
    return await service.search_assets(query=query, top_k=top_k)


@router.get("/search/intel", summary="Semantic threat intelligence search")
async def search_threat_intel(
    query: str = Query(..., description="Natural language search query"),
    top_k: int = Query(default=3, ge=1, le=10),
    threat_actor: str | None = Query(default=None),
    service: RAGService = Depends(get_rag_service),
):
    return await service.search_threat_intel(
        query=query,
        top_k=top_k,
        threat_actor=threat_actor,
    )


@router.get("/search/all", summary="Search across all collections")
async def search_all(
    query: str = Query(..., description="Natural language search query"),
    service: GraphRAGService = Depends(get_graphrag_service),
):
    return await service.semantic_attack_search(query=query)


@router.post("/ingest/cve", summary="Store a CVE in Qdrant")
async def ingest_cve(
    request: IngestCVERequest,
    service: RAGService = Depends(get_rag_service),
):
    point_id = await service.store_cve(
        cve_id=request.cve_id,
        description=request.description,
        cvss_score=request.cvss_score,
        severity=request.severity,
        affected_component=request.affected_component,
        cwe_id=request.cwe_id,
        is_exploitable=request.is_exploitable,
        has_public_exploit=request.has_public_exploit,
        exploit_maturity=request.exploit_maturity,
        published_date=request.published_date,
    )
    return {"status": "stored", "cve_id": request.cve_id, "point_id": point_id}


@router.post("/ingest/intel", summary="Store threat intelligence in Qdrant")
async def ingest_threat_intel(
    request: IngestIntelRequest,
    service: RAGService = Depends(get_rag_service),
):
    point_id = await service.store_threat_intel(
        intel_id=request.intel_id,
        title=request.title,
        content=request.content,
        source=request.source,
        threat_actor=request.threat_actor,
        techniques=request.techniques,
        severity=request.severity,
    )
    return {"status": "stored", "intel_id": request.intel_id, "point_id": point_id}
