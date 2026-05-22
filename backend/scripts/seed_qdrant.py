"""
scripts/seed_qdrant.py
=======================
Populates Qdrant with CVE descriptions and threat intel
matching the nodes already in Neo4j from seed_graph.py.

Run AFTER seed_graph.py:
    python scripts/seed_qdrant.py

Requires GEMINI_API_KEY in your .env file.
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.vectorstore.qdrant_client import qdrant_manager
from app.vectorstore.collections import initialize_collections
from app.services.rag_service import rag_service


async def seed():
    print("Connecting to Qdrant...")
    await qdrant_manager.connect()
    await initialize_collections()

    print("\nStoring CVEs in Qdrant...")

    cves = [
        {
            "cve_id": "CVE-2021-44228",
            "description": (
                "Apache Log4j2 Remote Code Execution vulnerability. "
                "JNDI features used in configuration, log messages, and parameters "
                "do not protect against attacker-controlled LDAP and other JNDI endpoints. "
                "An attacker who can control log messages can execute arbitrary code "
                "loaded from LDAP servers. Affects Log4j2 versions 2.0-beta9 to 2.14.1."
            ),
            "cvss_score": 10.0,
            "severity": "CRITICAL",
            "affected_component": "Apache Log4j2 2.0-beta9 through 2.14.1",
            "cwe_id": "CWE-502",
            "is_exploitable": True,
            "has_public_exploit": True,
            "exploit_maturity": "weaponized",
            "published_date": "2021-12-10",
        },
        {
            "cve_id": "CVE-2023-38408",
            "description": (
                "OpenSSH ssh-agent remote code execution vulnerability. "
                "A remote attacker who has access to a Unix domain socket for ssh-agent "
                "may be able to bypass checks and load a PKCS#11 provider from an "
                "arbitrary path, leading to remote code execution. "
                "Affects OpenSSH before 9.3p2."
            ),
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "affected_component": "OpenSSH before 9.3p2",
            "cwe_id": "CWE-426",
            "is_exploitable": True,
            "has_public_exploit": True,
            "exploit_maturity": "poc",
            "published_date": "2023-07-19",
        },
        {
            "cve_id": "CVE-2024-0056",
            "description": (
                "PostgreSQL authentication bypass vulnerability. "
                "Under specific pg_hba.conf configuration conditions, "
                "a remote attacker may authenticate without valid credentials. "
                "The issue stems from improper handling of certain authentication "
                "methods when combined with specific connection parameters."
            ),
            "cvss_score": 7.4,
            "severity": "HIGH",
            "affected_component": "PostgreSQL 14.x before 14.11",
            "cwe_id": "CWE-287",
            "is_exploitable": False,
            "has_public_exploit": False,
            "exploit_maturity": "unproven",
            "published_date": "2024-01-09",
        },
        {
            "cve_id": "CVE-2021-4034",
            "description": (
                "PwnKit: Local Privilege Escalation in polkit pkexec. "
                "A local privilege escalation vulnerability was found in polkit pkexec. "
                "pkexec does not properly handle argument arrays with zero elements, "
                "leading to out-of-bounds write. Any unprivileged local user can exploit "
                "this to become root. Affects all major Linux distributions. "
                "Weaponized exploits publicly available within hours of disclosure."
            ),
            "cvss_score": 7.8,
            "severity": "HIGH",
            "affected_component": "polkit pkexec",
            "cwe_id": "CWE-125",
            "is_exploitable": True,
            "has_public_exploit": True,
            "exploit_maturity": "weaponized",
            "published_date": "2022-01-25",
        },
    ]

    stored = await rag_service.store_cves_batch(cves)
    print(f"  Stored {stored} CVEs")

    print("\nStoring threat intelligence...")

    intel_items = [
        {
            "intel_id": "ti-log4shell-campaign",
            "title": "Log4Shell Mass Exploitation Campaign",
            "content": (
                "Widespread exploitation of CVE-2021-44228 observed within 24 hours "
                "of public disclosure. Threat actors including nation-state groups "
                "from China, Iran, North Korea, and Turkey observed exploiting the "
                "vulnerability for initial access. Common payloads include Cobalt Strike "
                "beacons, cryptocurrency miners, and ransomware droppers. "
                "Affected systems include Apache Struts, VMware vCenter, Cisco, "
                "and thousands of Java-based enterprise applications."
            ),
            "source": "CISA Alert AA21-356A",
            "threat_actor": "Multiple APT Groups",
            "techniques": ["T1190", "T1059", "T1027"],
            "severity": "CRITICAL",
        },
        {
            "intel_id": "ti-pwnkit-exploitation",
            "title": "PwnKit Local Privilege Escalation in the Wild",
            "content": (
                "CVE-2021-4034 (PwnKit) exploitation observed as post-exploitation "
                "technique after initial access via web application vulnerabilities. "
                "Commonly chained with web shell deployment for privilege escalation "
                "to root on Linux systems. Affects virtually all Linux distributions "
                "with polkit installed. Patch deployment critical for all Linux hosts."
            ),
            "source": "Qualys Threat Research",
            "threat_actor": "Various ransomware groups",
            "techniques": ["T1068", "T1548"],
            "severity": "HIGH",
        },
        {
            "intel_id": "ti-database-targeting",
            "title": "Database Server Targeting by Ransomware Groups",
            "content": (
                "Multiple ransomware operators observed specifically targeting "
                "PostgreSQL and MySQL database servers after lateral movement "
                "through web application infrastructure. Common attack chain: "
                "web server RCE -> app server pivot -> database server access -> "
                "data exfiltration -> encryption. Organizations should implement "
                "network segmentation isolating database servers from application tier."
            ),
            "source": "Internal Threat Research",
            "threat_actor": "LockBit, BlackCat, Cl0p",
            "techniques": ["T1486", "T1048", "T1021"],
            "severity": "CRITICAL",
        },
    ]

    for intel in intel_items:
        await rag_service.store_threat_intel(**intel)
        print(f"  Stored: {intel['title'][:50]}")

    print("\nStoring asset metadata...")
    await rag_service.store_asset_metadata(
        asset_id="host-203-0-113-10",
        name="web-server-01",
        asset_type="Web Server",
        description="Internet-facing nginx web server in DMZ. Runs Java application with Log4j2.",
        notes="Primary entry point for external traffic. Directly reachable from internet.",
        known_issues="Running Log4j2 version known to be vulnerable to CVE-2021-44228.",
        tags=["dmz", "internet-facing", "nginx", "java", "critical-path"],
    )

    await rag_service.store_asset_metadata(
        asset_id="db-postgres-main",
        name="production-db",
        asset_type="Database",
        description="Primary PostgreSQL production database. Contains customer PII and transaction records.",
        notes="Crown jewel asset. Contains GDPR-regulated personal data.",
        known_issues="Network segmentation insufficient — reachable from app server tier.",
        tags=["database", "pii", "critical", "postgresql", "crown-jewel"],
    )

    print("  Stored 2 asset metadata records")

    print("\n" + "="*50)
    print("QDRANT SEED COMPLETE")
    print("="*50)
    print("\nTest semantic search at:")
    print("  GET /api/v1/rag/search/cves?query=remote code execution")
    print("  GET /api/v1/rag/search/intel?query=ransomware database attack")
    print("  POST /api/v1/rag/analyze  {query: 'How can attacker reach database?'}")

    await qdrant_manager.disconnect()


if __name__ == "__main__":
    asyncio.run(seed())
