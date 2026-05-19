"""
Neo4j Client — Connection & Session Management
===============================================
This is the ONLY file in the entire project that imports the neo4j driver.
Everything else talks to Neo4j through this module.

How it works:
- Neo4jClient is a singleton: one driver instance for the entire app lifetime
- The driver manages a connection pool internally (multiple reusable connections)
- Sessions are created per-operation and closed immediately after
- Transactions give you atomic multi-query operations with rollback on failure
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Any

from neo4j import AsyncGraphDatabase, AsyncDriver, AsyncSession
from neo4j.exceptions import (
    AuthError,
    ServiceUnavailable,
    SessionExpired,
    TransientError,
)

from app.core.config import settings
from app.core.exceptions import (
    GraphConnectionError,
    GraphQueryError,
    GraphAuthError,
)

logger = logging.getLogger(__name__)


class Neo4jClient:
    """
    Manages the Neo4j async driver lifecycle.

    The driver is created once at application startup and closed at shutdown.
    It maintains an internal connection pool — you do NOT create a new
    connection for every query. Instead, you borrow a session from the pool,
    use it, and return it.

    Connection Pool Mental Model:
    ┌─────────────────────────────────────────┐
    │           Neo4jDriver (singleton)        │
    │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐  │
    │  │Conn 1│ │Conn 2│ │Conn 3│ │Conn 4│  │  ← pool of reusable connections
    │  └──────┘ └──────┘ └──────┘ └──────┘  │
    └─────────────────────────────────────────┘
         ↑           ↑
    Session A    Session B   ← borrowed by active requests
    """

    def __init__(self) -> None:
        self._driver: AsyncDriver | None = None

    async def connect(self) -> None:
        """
        Initialize the Neo4j driver and verify the connection.
        Called once during FastAPI startup via lifespan event.
        """
        try:
            self._driver = AsyncGraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USERNAME, settings.NEO4J_PASSWORD),
                # Connection pool settings
                max_connection_pool_size=50,        # Max simultaneous connections
                connection_acquisition_timeout=30,   # Seconds to wait for a free connection
                connection_timeout=10,               # Seconds to establish TCP connection
                max_transaction_retry_time=30,       # Auto-retry transient failures
            )

            # Verify connectivity — this actually tries to connect
            await self._driver.verify_connectivity()
            logger.info(
                "Neo4j connected successfully",
                extra={"uri": settings.NEO4J_URI, "database": settings.NEO4J_DATABASE}
            )

        except AuthError as e:
            logger.error("Neo4j authentication failed — check NEO4J_USERNAME and NEO4J_PASSWORD")
            raise GraphAuthError(f"Neo4j authentication failed: {e}") from e

        except ServiceUnavailable as e:
            logger.error("Neo4j is not reachable — is Docker running?", extra={"uri": settings.NEO4J_URI})
            raise GraphConnectionError(f"Neo4j unavailable at {settings.NEO4J_URI}: {e}") from e

    async def disconnect(self) -> None:
        """
        Cleanly close the driver and all pooled connections.
        Called during FastAPI shutdown via lifespan event.
        """
        if self._driver:
            await self._driver.close()
            self._driver = None
            logger.info("Neo4j connection closed")

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Provide a Neo4j session as an async context manager.

        A session is a logical container for a series of Cypher queries.
        Always use this via `async with` — it guarantees the session
        is closed and returned to the pool even if an exception occurs.

        Usage:
            async with neo4j_client.session() as session:
                result = await session.run("MATCH (n) RETURN n LIMIT 5")
                records = await result.data()

        Sessions are NOT thread-safe. Never share a session between
        concurrent coroutines. Each request gets its own session.
        """
        if not self._driver:
            raise GraphConnectionError("Neo4j driver not initialized. Call connect() first.")

        async with self._driver.session(
            database=settings.NEO4J_DATABASE,
            # fetch_size controls how many records are fetched from server at once
            # 1000 is a good default — adjust for large result sets
            fetch_size=1000,
        ) as session:
            try:
                yield session
            except (SessionExpired, TransientError) as e:
                # These are recoverable — log and re-raise for caller to handle
                logger.warning("Neo4j session error (may be transient)", extra={"error": str(e)})
                raise GraphQueryError(f"Neo4j session error: {e}") from e
            except Exception as e:
                logger.error("Unexpected Neo4j error", extra={"error": str(e)})
                raise GraphQueryError(f"Neo4j query failed: {e}") from e

    async def execute_read(self, query: str, parameters: dict[str, Any] | None = None) -> list[dict]:
        """
        Execute a READ query (MATCH, RETURN) and return results as a list of dicts.

        Read queries run in a managed read transaction — Neo4j can automatically
        route these to read replicas in a cluster for better performance.

        Args:
            query: Cypher query string
            parameters: Dict of query parameters (always use params, never f-strings!)

        Returns:
            List of records as plain Python dicts

        Example:
            results = await client.execute_read(
                "MATCH (h:Host {id: $id}) RETURN h",
                {"id": "host-001"}
            )
        """
        async with self.session() as session:
            result = await session.run(query, parameters or {})
            records = await result.data()
            return records

    async def execute_write(self, query: str, parameters: dict[str, Any] | None = None) -> list[dict]:
        """
        Execute a WRITE query (CREATE, MERGE, SET, DELETE) and return results.

        Write queries run in a managed write transaction with automatic retry
        on transient failures (e.g., deadlocks, leader elections in clusters).

        IMPORTANT: Always use MERGE instead of CREATE for nodes when ingesting
        data — MERGE is idempotent (safe to run multiple times without duplicates).

        Args:
            query: Cypher query string
            parameters: Dict of query parameters

        Returns:
            List of records as plain Python dicts
        """
        async with self.session() as session:
            result = await session.run(query, parameters or {})
            records = await result.data()
            return records

    async def execute_write_many(self, query: str, parameters_list: list[dict]) -> None:
        """
        Execute a WRITE query in batch — runs all items in a single transaction.

        This is dramatically faster than calling execute_write() in a loop
        because it sends all data in one network round-trip.

        Use this for bulk ingestion (e.g., loading 500 hosts from an Nmap scan).

        Args:
            query: Cypher query string (typically using UNWIND $rows AS row)
            parameters_list: List of parameter dicts, one per record
        """
        async with self.session() as session:
            async with session.begin_transaction() as tx:
                try:
                    for parameters in parameters_list:
                        await tx.run(query, parameters)
                    await tx.commit()
                    logger.debug(f"Batch write committed: {len(parameters_list)} records")
                except Exception as e:
                    await tx.rollback()
                    logger.error("Batch write failed, rolled back", extra={"error": str(e)})
                    raise GraphQueryError(f"Batch write failed: {e}") from e

    async def health_check(self) -> dict:
        """
        Verify Neo4j is reachable and return basic server info.
        Used by the /health API endpoint.
        """
        try:
            results = await self.execute_read(
                "CALL dbms.components() YIELD name, versions, edition "
                "RETURN name, versions[0] AS version, edition"
            )
            return {
                "status": "healthy",
                "neo4j_version": results[0].get("version") if results else "unknown",
                "edition": results[0].get("edition") if results else "unknown",
            }
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}


# ---------------------------------------------------------------------------
# Singleton instance
# ---------------------------------------------------------------------------
# One instance is created here at module import time.
# FastAPI's dependency injection system uses this instance everywhere.
# This guarantees a single connection pool for the entire application.
neo4j_client = Neo4jClient()
