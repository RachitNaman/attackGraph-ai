"""
core/exceptions.py
==================
Custom exception hierarchy for AttackGraph AI.

WHY CUSTOM EXCEPTIONS?
- Raw Python exceptions (ValueError, RuntimeError) give no context
- Custom exceptions let you handle specific failure modes differently
- FastAPI's exception handlers convert these into clean HTTP responses
- Logging becomes meaningful: "GraphConnectionError" vs "Exception"

HIERARCHY:
    AttackGraphException (base)
    ├── GraphConnectionError    → Neo4j unreachable
    ├── GraphAuthError          → Bad Neo4j credentials
    ├── GraphQueryError         → Cypher query failed
    ├── AssetNotFoundError      → Node doesn't exist in graph
    ├── VectorStoreError        → Qdrant operation failed
    ├── EmbeddingError          → Gemini embedding failed
    ├── AgentError              → LangGraph agent failure
    └── IngestionError          → Data ingestion pipeline failure
"""

from fastapi import Request
from fastapi.responses import JSONResponse
import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Base Exception
# ---------------------------------------------------------------------------

class AttackGraphException(Exception):
    """Base exception for all AttackGraph AI errors."""
    def __init__(self, message: str, code: str = "INTERNAL_ERROR"):
        self.message = message
        self.code = code
        super().__init__(message)


# ---------------------------------------------------------------------------
# Graph / Neo4j Exceptions
# ---------------------------------------------------------------------------

class GraphConnectionError(AttackGraphException):
    """Neo4j is unreachable or connection pool is exhausted."""
    def __init__(self, message: str):
        super().__init__(message, code="GRAPH_CONNECTION_ERROR")


class GraphAuthError(AttackGraphException):
    """Neo4j authentication failed (wrong username/password)."""
    def __init__(self, message: str):
        super().__init__(message, code="GRAPH_AUTH_ERROR")


class GraphQueryError(AttackGraphException):
    """A Cypher query failed to execute."""
    def __init__(self, message: str):
        super().__init__(message, code="GRAPH_QUERY_ERROR")


class AssetNotFoundError(AttackGraphException):
    """A requested node (Host, Service, etc.) doesn't exist in the graph."""
    def __init__(self, message: str):
        super().__init__(message, code="ASSET_NOT_FOUND")


# ---------------------------------------------------------------------------
# Vector Store Exceptions
# ---------------------------------------------------------------------------

class VectorStoreError(AttackGraphException):
    """Qdrant operation failed."""
    def __init__(self, message: str):
        super().__init__(message, code="VECTOR_STORE_ERROR")


class EmbeddingError(AttackGraphException):
    """Gemini embedding generation failed."""
    def __init__(self, message: str):
        super().__init__(message, code="EMBEDDING_ERROR")


# ---------------------------------------------------------------------------
# Agent / AI Exceptions
# ---------------------------------------------------------------------------

class AgentError(AttackGraphException):
    """LangGraph agent encountered an unrecoverable error."""
    def __init__(self, message: str):
        super().__init__(message, code="AGENT_ERROR")


# ---------------------------------------------------------------------------
# Ingestion Exceptions
# ---------------------------------------------------------------------------

class IngestionError(AttackGraphException):
    """Data ingestion pipeline failed."""
    def __init__(self, message: str):
        super().__init__(message, code="INGESTION_ERROR")


class ParseError(AttackGraphException):
    """File parsing failed (invalid Nmap XML, malformed Nessus file, etc.)."""
    def __init__(self, message: str):
        super().__init__(message, code="PARSE_ERROR")


# ---------------------------------------------------------------------------
# FastAPI Exception Handlers
# Register these in main.py using app.add_exception_handler()
# ---------------------------------------------------------------------------

async def attackgraph_exception_handler(request: Request, exc: AttackGraphException) -> JSONResponse:
    """Convert AttackGraph exceptions into structured JSON error responses."""
    status_map = {
        "ASSET_NOT_FOUND": 404,
        "GRAPH_AUTH_ERROR": 503,
        "GRAPH_CONNECTION_ERROR": 503,
        "GRAPH_QUERY_ERROR": 500,
        "VECTOR_STORE_ERROR": 500,
        "EMBEDDING_ERROR": 500,
        "AGENT_ERROR": 500,
        "INGESTION_ERROR": 422,
        "PARSE_ERROR": 422,
    }

    status_code = status_map.get(exc.code, 500)

    logger.error(
        "AttackGraph exception",
        extra={"code": exc.code, "message": exc.message, "path": str(request.url)}
    )

    return JSONResponse(
        status_code=status_code,
        content={
            "error": exc.code,
            "message": exc.message,
            "path": str(request.url),
        }
    )


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all for unexpected exceptions — never expose stack traces."""
    logger.exception("Unhandled exception", extra={"path": str(request.url)})
    return JSONResponse(
        status_code=500,
        content={
            "error": "INTERNAL_ERROR",
            "message": "An unexpected error occurred. Please try again.",
            "path": str(request.url),
        }
    )
