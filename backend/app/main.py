"""
main.py — FastAPI application entry point.

STARTUP ORDER:
1. Neo4j connects + schema initialized
2. Qdrant connects + collections initialized
3. App ready to serve requests

SHUTDOWN:
1. Neo4j disconnects
2. Qdrant disconnects
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.exceptions import (
    AttackGraphException,
    attackgraph_exception_handler,
    generic_exception_handler,
)
from app.graph.neo4j_client import neo4j_client
from app.graph.schema.constraints import schema_manager
from app.vectorstore.qdrant_client import qdrant_manager
from app.vectorstore.collections import initialize_collections

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""

    # ── STARTUP ──────────────────────────────────────────────────────────
    logger.info(f"Starting {settings.APP_NAME} [{settings.APP_ENV}]")

    # Neo4j
    logger.info("Connecting to Neo4j...")
    await neo4j_client.connect()
    await schema_manager.initialize()

    # Qdrant
    logger.info("Connecting to Qdrant...")
    await qdrant_manager.connect()
    await initialize_collections()

    logger.info(f"{settings.APP_NAME} startup complete — ready to serve")

    yield  # Application runs here

    # ── SHUTDOWN ─────────────────────────────────────────────────────────
    logger.info("Shutting down...")
    await neo4j_client.disconnect()
    await qdrant_manager.disconnect()
    logger.info("All connections closed.")


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        description="AI-powered cyber attack path analysis platform",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.FRONTEND_URL, "http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Exception handlers
    app.add_exception_handler(AttackGraphException, attackgraph_exception_handler)
    app.add_exception_handler(Exception, generic_exception_handler)

    # Routers
    from app.api.v1 import graph, health, traversal, rag
    app.include_router(graph.router,     prefix="/api/v1/graph",     tags=["Graph"])
    app.include_router(traversal.router, prefix="/api/v1/traversal", tags=["Traversal"])
    app.include_router(rag.router,       prefix="/api/v1/rag",       tags=["RAG"])
    app.include_router(health.router,    prefix="/api/v1",           tags=["Health"])

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=settings.APP_DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
    )
