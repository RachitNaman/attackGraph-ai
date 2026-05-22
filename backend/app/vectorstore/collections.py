"""
vectorstore/collections.py
===========================
Qdrant collection definitions — names, schema, and initialization.

Three collections for AttackGraph AI:

1. cve_descriptions
   Stores: CVE description text, severity, CVSS, affected components
   Used for: "Find vulnerabilities similar to Log4Shell"
             "What CVEs involve remote code execution in web servers?"

2. asset_metadata
   Stores: Asset description text, role, known issues, notes
   Used for: "Find servers similar to this legacy SAP instance"
             "What assets are described as unpatched or legacy?"

3. threat_intel
   Stores: MITRE ATT&CK techniques, threat actor TTPs, IOCs
   Used for: "What techniques does APT29 use?"
             "Find attacks similar to this observed behavior"
"""

import logging
from app.vectorstore.qdrant_client import qdrant_manager
from app.core.config import settings

logger = logging.getLogger(__name__)

# Collection name constants — import these everywhere
# Never use raw strings like "cve_descriptions" in other files
CVE_COLLECTION = settings.QDRANT_CVE_COLLECTION           # "cve_descriptions"
ASSETS_COLLECTION = settings.QDRANT_ASSETS_COLLECTION     # "asset_metadata"
THREAT_INTEL_COLLECTION = settings.QDRANT_THREAT_INTEL_COLLECTION  # "threat_intel"

VECTOR_SIZE = settings.EMBEDDING_DIMENSIONS               # 768 for Gemini


async def initialize_collections() -> None:
    """
    Create all Qdrant collections at startup.
    Safe to call every startup — idempotent.
    Called from main.py lifespan after Qdrant connects.
    """
    logger.info("Initializing Qdrant collections...")

    await qdrant_manager.ensure_collection(CVE_COLLECTION, VECTOR_SIZE)
    await qdrant_manager.ensure_collection(ASSETS_COLLECTION, VECTOR_SIZE)
    await qdrant_manager.ensure_collection(THREAT_INTEL_COLLECTION, VECTOR_SIZE)

    # Log counts for visibility
    cve_count = await qdrant_manager.count_points(CVE_COLLECTION)
    asset_count = await qdrant_manager.count_points(ASSETS_COLLECTION)
    intel_count = await qdrant_manager.count_points(THREAT_INTEL_COLLECTION)

    logger.info(
        f"Qdrant collections ready: "
        f"CVEs={cve_count}, Assets={asset_count}, ThreatIntel={intel_count}"
    )
