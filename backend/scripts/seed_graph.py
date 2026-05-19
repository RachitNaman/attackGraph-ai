"""
scripts/seed_graph.py
=====================
Development seed script — populates Neo4j with a realistic sample network.

This creates a mini attack scenario:
  Internet → Web Server (CVE-2024-1234) → App Server → Database
                                        ↘ Admin User

Run from the backend/ folder with venv active:
    python scripts/seed_graph.py

What it creates:
- 4 Hosts (1 internet-facing web server, 2 internal, 1 database host)
- 1 Database node
- 1 Admin User
- 6 Services (HTTP, HTTPS, SSH, PostgreSQL, etc.)
- 4 Vulnerabilities (mix of CVSS scores)
- All appropriate relationships
"""

import asyncio
import sys
import os

# Add backend/ to Python path so imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.graph.neo4j_client import neo4j_client
from app.graph.schema.constraints import schema_manager
from app.services.graph_service import GraphService


async def seed():
    print("Connecting to Neo4j...")
    await neo4j_client.connect()
    await schema_manager.initialize()

    service = GraphService()

    print("\nCreating hosts...")

    # Internet-facing web server — entry point for attacker
    web_server = await service.create_host(
        ip_address="203.0.113.10",
        hostname="web-server-01",
        os="Linux",
        os_version="Ubuntu 22.04",
        subnet="203.0.113.0/24",
        is_internet_facing=True,
        is_critical=False,
        asset_group="DMZ",
    )
    print(f"  ✓ {web_server.hostname} ({web_server.ip_address}) [internet-facing]")

    # Internal app server
    app_server = await service.create_host(
        ip_address="10.0.1.20",
        hostname="app-server-01",
        os="Linux",
        os_version="CentOS 7",
        subnet="10.0.1.0/24",
        is_internet_facing=False,
        is_critical=False,
        asset_group="Internal",
    )
    print(f"  ✓ {app_server.hostname} ({app_server.ip_address})")

    # Database host — the crown jewel
    db_host = await service.create_host(
        ip_address="10.0.2.50",
        hostname="db-server-01",
        os="Linux",
        os_version="Ubuntu 20.04",
        subnet="10.0.2.0/24",
        is_internet_facing=False,
        is_critical=True,
        asset_group="Internal",
    )
    print(f"  ✓ {db_host.hostname} ({db_host.ip_address}) [critical]")

    # Jump server
    jump_server = await service.create_host(
        ip_address="10.0.1.5",
        hostname="jump-server-01",
        os="Windows",
        os_version="Windows Server 2019",
        subnet="10.0.1.0/24",
        is_internet_facing=False,
        is_critical=False,
        asset_group="Internal",
    )
    print(f"  ✓ {jump_server.hostname} ({jump_server.ip_address})")

    print("\nCreating services...")

    # Web server services
    await service.create_service(web_server.id, port=80,  protocol="tcp", name="nginx",    version="1.18.0", is_encrypted=False)
    await service.create_service(web_server.id, port=443, protocol="tcp", name="nginx",    version="1.18.0", is_encrypted=True)
    await service.create_service(web_server.id, port=22,  protocol="tcp", name="openssh",  version="8.9",    is_encrypted=True)

    # App server services
    await service.create_service(app_server.id, port=8080, protocol="tcp", name="tomcat",  version="9.0.65", is_encrypted=False)
    await service.create_service(app_server.id, port=22,   protocol="tcp", name="openssh", version="7.4",    is_encrypted=True)

    # Database host services
    await service.create_service(db_host.id, port=5432, protocol="tcp", name="postgresql", version="14.2",   is_encrypted=False)

    print("  ✓ 6 services created")

    print("\nCreating vulnerabilities...")

    # Critical RCE on the web server (Log4Shell style)
    cve1 = await service.create_vulnerability(
        cve_id="CVE-2021-44228",
        description="Apache Log4j2 Remote Code Execution vulnerability. "
                    "Allows unauthenticated remote attackers to execute arbitrary code "
                    "via a specially crafted JNDI lookup request.",
        cvss_score=10.0,
        severity="CRITICAL",
        affected_component="Apache Log4j2 2.0-beta9 through 2.14.1",
        cwe_id="CWE-502",
        is_exploitable=True,
        has_public_exploit=True,
        exploit_maturity="weaponized",
        patch_available=True,
    )
    print(f"  ✓ {cve1.cve_id} (CVSS: {cve1.cvss_score} CRITICAL)")

    # High severity SSH vulnerability
    cve2 = await service.create_vulnerability(
        cve_id="CVE-2023-38408",
        description="OpenSSH ssh-agent remote code execution vulnerability. "
                    "A remote attacker can execute arbitrary code on systems running "
                    "vulnerable versions of OpenSSH.",
        cvss_score=9.8,
        severity="CRITICAL",
        affected_component="OpenSSH before 9.3p2",
        cwe_id="CWE-426",
        is_exploitable=True,
        has_public_exploit=True,
        exploit_maturity="poc",
        patch_available=True,
    )
    print(f"  ✓ {cve2.cve_id} (CVSS: {cve2.cvss_score} CRITICAL)")

    # Medium severity info disclosure
    cve3 = await service.create_vulnerability(
        cve_id="CVE-2024-0056",
        description="PostgreSQL authentication bypass vulnerability allowing "
                    "an attacker to connect without valid credentials under "
                    "specific configuration conditions.",
        cvss_score=7.4,
        severity="HIGH",
        affected_component="PostgreSQL 14.x before 14.11",
        cwe_id="CWE-287",
        is_exploitable=False,
        has_public_exploit=False,
        exploit_maturity="unproven",
        patch_available=True,
    )
    print(f"  ✓ {cve3.cve_id} (CVSS: {cve3.cvss_score} HIGH)")

    # Privilege escalation vulnerability
    cve4 = await service.create_vulnerability(
        cve_id="CVE-2021-4034",
        description="PwnKit: Local Privilege Escalation in polkit pkexec. "
                    "Allows any unprivileged local user to escalate to root.",
        cvss_score=7.8,
        severity="HIGH",
        affected_component="polkit pkexec",
        cwe_id="CWE-125",
        is_exploitable=True,
        has_public_exploit=True,
        exploit_maturity="weaponized",
        patch_available=True,
    )
    print(f"  ✓ {cve4.cve_id} (CVSS: {cve4.cvss_score} HIGH) [priv esc]")

    print("\nLinking vulnerabilities to hosts...")
    await service.link_vulnerability_to_host(web_server.id, cve1.cve_id, scanner="nessus")
    await service.link_vulnerability_to_host(web_server.id, cve2.cve_id, scanner="nessus")
    await service.link_vulnerability_to_host(app_server.id, cve4.cve_id, scanner="nessus")
    await service.link_vulnerability_to_host(db_host.id,   cve3.cve_id, scanner="nessus")
    print("  ✓ 4 host-vulnerability links created")

    print("\nCreating network connections...")
    # These represent network paths an attacker can traverse
    await neo4j_client.execute_write(
        """
        MATCH (a {id: $a_id}), (b {id: $b_id})
        MERGE (a)-[r:CONNECTS_TO]->(b)
        ON CREATE SET r.port = $port, r.protocol = 'tcp', r.created_at = datetime()
        """,
        {"a_id": web_server.id, "b_id": app_server.id, "port": 8080}
    )
    await neo4j_client.execute_write(
        """
        MATCH (a {id: $a_id}), (b {id: $b_id})
        MERGE (a)-[r:CONNECTS_TO]->(b)
        ON CREATE SET r.port = $port, r.protocol = 'tcp', r.created_at = datetime()
        """,
        {"a_id": app_server.id, "b_id": db_host.id, "port": 5432}
    )
    await neo4j_client.execute_write(
        """
        MATCH (a {id: $a_id}), (b {id: $b_id})
        MERGE (a)-[r:CONNECTS_TO]->(b)
        ON CREATE SET r.port = 22, r.protocol = 'tcp', r.created_at = datetime()
        """,
        {"a_id": web_server.id, "b_id": jump_server.id}
    )
    print("  ✓ Network connections created")

    print("\nCreating database node...")
    await neo4j_client.execute_write(
        """
        MERGE (db:Database {id: 'db-postgres-main'})
        ON CREATE SET
            db.name = 'production-db',
            db.type = 'postgresql',
            db.version = '14.2',
            db.port = 5432,
            db.contains_pii = true,
            db.contains_secrets = false,
            db.is_encrypted = false,
            db.created_at = datetime()
        WITH db
        MATCH (h:Host {id: $host_id})
        MERGE (h)-[:RUNS]->(db)
        """,
        {"host_id": db_host.id}
    )
    print("  ✓ PostgreSQL database node created and linked to host")

    print("\nCreating admin user...")
    await neo4j_client.execute_write(
        """
        MERGE (u:User {id: 'user-admin-root'})
        ON CREATE SET
            u.username = 'root',
            u.display_name = 'Root User',
            u.is_admin = true,
            u.is_service_account = false,
            u.created_at = datetime()
        WITH u
        MATCH (db:Database {id: 'db-postgres-main'})
        MERGE (u)-[r:CAN_ACCESS]->(db)
        ON CREATE SET r.access_level = 'admin', r.created_at = datetime()
        """,
        {}
    )

    # PwnKit escalates to root
    await neo4j_client.execute_write(
        """
        MATCH (v:Vulnerability {cve_id: 'CVE-2021-4034'})
        MATCH (u:User {id: 'user-admin-root'})
        MERGE (v)-[r:ESCALATES_TO]->(u)
        ON CREATE SET r.technique = 'local_privilege_escalation', r.created_at = datetime()
        """,
        {}
    )
    print("  ✓ Admin user created with database access")
    print("  ✓ CVE-2021-4034 escalation path linked to root")

    # Final summary
    summary = await service.get_graph_summary()
    print("\n" + "="*50)
    print("SEED COMPLETE — Graph Summary:")
    print("="*50)
    for label, count in summary.node_counts.items():
        print(f"  {label:<20} {count} nodes")
    print()
    for rel_type, count in summary.relationship_counts.items():
        print(f"  {rel_type:<25} {count} relationships")

    print("\nAttack path preview (Internet → Database):")
    paths = await service.find_paths_to_database(max_hops=8, limit=3)
    for i, path in enumerate(paths, 1):
        nodes = " → ".join(n.get("name", n.get("id", "?")) for n in path.get("path_nodes", []))
        print(f"  Path {i} ({path.get('hop_count')} hops): {nodes}")

    await neo4j_client.disconnect()
    print("\nDone! Open Neo4j Browser at http://localhost:7474 to explore the graph.")
    print("Query: MATCH (n) RETURN n LIMIT 50")


if __name__ == "__main__":
    asyncio.run(seed())
