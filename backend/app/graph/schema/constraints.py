"""
Graph Schema — Constraints & Indexes
=====================================
This file defines the Neo4j schema: constraints and indexes.

WHY CONSTRAINTS?
- Uniqueness constraints prevent duplicate nodes (e.g., two Host nodes with the same ID)
- They also automatically create an index, speeding up lookups by that property
- They enforce data integrity at the database level, not just application level

WHY INDEXES?
- Without an index, Neo4j must scan EVERY node of a label to find matches
- With an index, it jumps directly to matching nodes
- Critical for performance when your graph has thousands of nodes

WHEN TO RUN THIS:
- Once, when the application starts for the first time
- Safe to run again — all statements use IF NOT EXISTS
- Run via: await schema_manager.initialize()

NODE LABELS IN THIS PROJECT:
┌─────────────────────────────────────────────────────────────────┐
│  Label         │ Represents                                      │
│────────────────│─────────────────────────────────────────────── │
│  Host          │ Server, workstation, VM, container              │
│  Service       │ Running process (HTTP, SSH, DB listener)        │
│  Vulnerability │ A CVE or weakness on a host/service             │
│  User          │ OS user, service account, admin account         │
│  Database      │ Database instance (PostgreSQL, MySQL, etc.)     │
│  Firewall      │ Firewall rule or network boundary               │
└─────────────────────────────────────────────────────────────────┘

RELATIONSHIP TYPES IN THIS PROJECT:
┌─────────────────────────────────────────────────────────────────┐
│  Type              │ Meaning                                     │
│────────────────────│──────────────────────────────────────────── │
│  RUNS              │ Host RUNS Service                           │
│  CONNECTS_TO       │ Host/Service CONNECTS_TO Host/Service       │
│  HAS_VULNERABILITY │ Host/Service HAS_VULNERABILITY Vulnerability│
│  CAN_ACCESS        │ User/Service CAN_ACCESS Database/Host       │
│  ESCALATES_TO      │ Vulnerability ESCALATES_TO User (priv esc) │
└─────────────────────────────────────────────────────────────────┘
"""

import logging
from app.graph.neo4j_client import neo4j_client

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constraint Definitions
# ---------------------------------------------------------------------------
# Format: (label, property, constraint_name)
# Uniqueness constraint = unique property + automatic index
NODE_CONSTRAINTS = [
    ("Host",          "id",  "host_id_unique"),
    ("Service",       "id",  "service_id_unique"),
    ("Vulnerability", "cve_id", "vulnerability_cve_unique"),
    ("User",          "id",  "user_id_unique"),
    ("Database",      "id",  "database_id_unique"),
    ("Firewall",      "id",  "firewall_id_unique"),
]

# ---------------------------------------------------------------------------
# Additional Index Definitions (non-unique properties we query often)
# ---------------------------------------------------------------------------
# Format: (label, property, index_name)
ADDITIONAL_INDEXES = [
    # Host indexes — common query filters
    ("Host",          "ip_address",  "host_ip_idx"),
    ("Host",          "hostname",    "host_hostname_idx"),
    ("Host",          "subnet",      "host_subnet_idx"),
    ("Host",          "os",          "host_os_idx"),

    # Service indexes
    ("Service",       "port",        "service_port_idx"),
    ("Service",       "protocol",    "service_protocol_idx"),
    ("Service",       "name",        "service_name_idx"),

    # Vulnerability indexes — heavily queried for attack path analysis
    ("Vulnerability", "cvss_score",  "vuln_cvss_idx"),
    ("Vulnerability", "severity",    "vuln_severity_idx"),
    ("Vulnerability", "is_exploitable", "vuln_exploitable_idx"),

    # User indexes
    ("User",          "username",    "user_username_idx"),
    ("User",          "is_admin",    "user_admin_idx"),

    # Database indexes
    ("Database",      "type",        "db_type_idx"),
    ("Database",      "name",        "db_name_idx"),
]


class SchemaManager:
    """
    Manages Neo4j schema initialization.
    All methods are idempotent — safe to run multiple times.
    """

    async def initialize(self) -> None:
        """
        Full schema initialization. Call this once at application startup.
        Creates all constraints and indexes if they don't already exist.
        """
        logger.info("Initializing Neo4j schema...")
        await self._create_constraints()
        await self._create_indexes()
        await self._verify_schema()
        logger.info("Neo4j schema initialization complete")

    async def _create_constraints(self) -> None:
        """Create uniqueness constraints for all node types."""
        for label, prop, name in NODE_CONSTRAINTS:
            query = (
                f"CREATE CONSTRAINT {name} IF NOT EXISTS "
                f"FOR (n:{label}) REQUIRE n.{prop} IS UNIQUE"
            )
            try:
                await neo4j_client.execute_write(query)
                logger.debug(f"Constraint ensured: {name}")
            except Exception as e:
                logger.error(f"Failed to create constraint {name}: {e}")
                raise

    async def _create_indexes(self) -> None:
        """Create additional indexes for frequently queried properties."""
        for label, prop, name in ADDITIONAL_INDEXES:
            query = (
                f"CREATE INDEX {name} IF NOT EXISTS "
                f"FOR (n:{label}) ON (n.{prop})"
            )
            try:
                await neo4j_client.execute_write(query)
                logger.debug(f"Index ensured: {name}")
            except Exception as e:
                logger.error(f"Failed to create index {name}: {e}")
                raise

    async def _verify_schema(self) -> None:
        """Log all active constraints and indexes for verification."""
        constraints = await neo4j_client.execute_read("SHOW CONSTRAINTS")
        indexes = await neo4j_client.execute_read("SHOW INDEXES")

        logger.info(f"Schema verified: {len(constraints)} constraints, {len(indexes)} indexes active")

    async def drop_all(self) -> None:
        """
        WARNING: Drops all constraints and indexes.
        ONLY use in development/testing to reset the schema.
        Never call this in production.
        """
        logger.warning("Dropping all Neo4j constraints and indexes — DEV ONLY")

        for _, __, name in NODE_CONSTRAINTS:
            await neo4j_client.execute_write(f"DROP CONSTRAINT {name} IF EXISTS")

        for _, __, name in ADDITIONAL_INDEXES:
            await neo4j_client.execute_write(f"DROP INDEX {name} IF EXISTS")

        logger.warning("All constraints and indexes dropped")


# Singleton instance
schema_manager = SchemaManager()
