"""
main.py
=======
FastAPI application entry point.

WHAT HAPPENS AT STARTUP:
1. lifespan() runs — connects to Neo4j, Qdrant, Redis
2. Schema is initialized — constraints and indexes created
3. FastAPI app is ready to serve requests

WHAT HAPPENS AT SHUTDOWN:
1. lifespan() cleanup runs — all connections closed cleanly
2. No data loss, no hanging connections
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

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lifespan — startup and shutdown logic
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager.
    Code before `yield` runs at startup.
    Code after `yield` runs at shutdown.
    """
    # ── STARTUP ──────────────────────────────────────────────────────────
    logger.info(f"Starting {settings.APP_NAME} in {settings.APP_ENV} mode")

    # Connect to Neo4j
    logger.info("Connecting to Neo4j...")
    await neo4j_client.connect()

    # Initialize graph schema (idempotent — safe to run every startup)
    logger.info("Initializing graph schema...")
    await schema_manager.initialize()

    # TODO: Connect to Qdrant (added in vectorstore module)
    # await qdrant_client.connect()

    logger.info(f"{settings.APP_NAME} startup complete")

    yield  # ← Application runs here, handling requests

    # ── SHUTDOWN ─────────────────────────────────────────────────────────
    logger.info("Shutting down...")
    await neo4j_client.disconnect()
    logger.info("All connections closed. Goodbye.")


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        description="AI-powered cyber attack path analysis platform",
        version="0.1.0",
        docs_url="/docs",           # Swagger UI at /docs
        redoc_url="/redoc",         # ReDoc at /redoc
        lifespan=lifespan,
    )

    # ── Middleware ────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.FRONTEND_URL, "http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Exception Handlers ────────────────────────────────────────────────
    app.add_exception_handler(AttackGraphException, attackgraph_exception_handler)
    app.add_exception_handler(Exception, generic_exception_handler)

    # ── Routers ───────────────────────────────────────────────────────────
    from app.api.v1 import graph, health, traversal
    app.include_router(graph.router,     prefix="/api/v1/graph",     tags=["Graph"])
    app.include_router(traversal.router, prefix="/api/v1/traversal", tags=["Traversal"])
    app.include_router(health.router,    prefix="/api/v1",           tags=["Health"])

    return app


app = create_app()


# ---------------------------------------------------------------------------
# Run directly with: python -m app.main
# Or with uvicorn: uvicorn app.main:app --reload
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=settings.APP_DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
    )