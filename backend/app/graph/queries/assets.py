"""
Asset & Vulnerability Queries
==============================
Cypher queries for creating, reading, and managing asset nodes.
All write queries use MERGE (not CREATE) to be idempotent.

MERGE vs CREATE explained:
- CREATE always creates a new node — can cause duplicates
- MERGE matches existing node OR creates new one if not found
- MERGE + ON CREATE SET → set properties only when creating new node
- MERGE + ON MATCH SET  → update properties when node already exists
"""


# ===========================================================================
# HOST NODE QUERIES
# ===========================================================================

MERGE_HOST = """
MERGE (h:Host {id: $id})
ON CREATE SET
    h.ip_address        = $ip_address,
    h.hostname          = $hostname,
    h.os                = $os,
    h.os_version        = $os_version,
    h.subnet            = $subnet,
    h.is_internet_facing = $is_internet_facing,
    h.is_critical       = $is_critical,
    h.asset_group       = $asset_group,
    h.created_at        = datetime()
ON MATCH SET
    h.ip_address        = $ip_address,
    h.hostname          = $hostname,
    h.os                = $os,
    h.os_version        = $os_version,
    h.is_internet_facing = $is_internet_facing,
    h.updated_at        = datetime()
RETURN h
"""
# Host properties:
# id               → unique identifier (e.g., "host-192-168-1-10")
# ip_address       → "192.168.1.10"
# hostname         → "web-server-01"
# os               → "Linux", "Windows Server 2019"
# os_version       → "Ubuntu 22.04"
# subnet           → "192.168.1.0/24"
# is_internet_facing → true = exposed to internet, high priority for attackers
# is_critical      → true = database server, AD controller, etc.
# asset_group      → "DMZ", "Internal", "Cloud"


GET_HOST_BY_ID = """
MATCH (h:Host {id: $id})
OPTIONAL MATCH (h)-[:RUNS]->(s:Service)
OPTIONAL MATCH (h)-[:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN h,
       collect(DISTINCT s) AS services,
       collect(DISTINCT v) AS vulnerabilities
"""


GET_HOST_BY_IP = """
MATCH (h:Host {ip_address: $ip_address})
RETURN h
"""


GET_ALL_HOSTS = """
MATCH (h:Host)
OPTIONAL MATCH (h)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WITH h, count(v) AS vuln_count
RETURN h, vuln_count
ORDER BY h.is_internet_facing DESC, vuln_count DESC
SKIP $skip
LIMIT $limit
"""


GET_INTERNET_FACING_HOSTS = """
MATCH (h:Host {is_internet_facing: true})
OPTIONAL MATCH (h)-[:RUNS]->(s:Service)
OPTIONAL MATCH (h)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WITH h,
     collect(DISTINCT {port: s.port, name: s.name, protocol: s.protocol}) AS services,
     count(DISTINCT v) AS vuln_count
RETURN h, services, vuln_count
ORDER BY vuln_count DESC
"""


# ===========================================================================
# SERVICE NODE QUERIES
# ===========================================================================

MERGE_SERVICE = """
MERGE (s:Service {id: $id})
ON CREATE SET
    s.name        = $name,
    s.port        = $port,
    s.protocol    = $protocol,
    s.version     = $version,
    s.banner      = $banner,
    s.is_encrypted = $is_encrypted,
    s.created_at  = datetime()
ON MATCH SET
    s.version     = $version,
    s.banner      = $banner,
    s.updated_at  = datetime()
RETURN s
"""
# Service properties:
# id           → "svc-192-168-1-10-80"
# name         → "nginx", "openssh", "postgresql"
# port         → 80, 443, 22, 5432
# protocol     → "tcp", "udp"
# version      → "nginx/1.18.0"
# banner       → raw service banner (useful for fingerprinting)
# is_encrypted → false for HTTP (attacker can sniff), true for HTTPS


CREATE_RUNS_RELATIONSHIP = """
MATCH (h:Host {id: $host_id})
MATCH (s:Service {id: $service_id})
MERGE (h)-[r:RUNS]->(s)
ON CREATE SET r.created_at = datetime()
RETURN r
"""


# ===========================================================================
# VULNERABILITY NODE QUERIES
# ===========================================================================

MERGE_VULNERABILITY = """
MERGE (v:Vulnerability {cve_id: $cve_id})
ON CREATE SET
    v.id                 = $id,
    v.description        = $description,
    v.cvss_score         = $cvss_score,
    v.cvss_vector        = $cvss_vector,
    v.severity           = $severity,
    v.cwe_id             = $cwe_id,
    v.affected_component = $affected_component,
    v.is_exploitable     = $is_exploitable,
    v.has_public_exploit = $has_public_exploit,
    v.exploit_maturity   = $exploit_maturity,
    v.patch_available    = $patch_available,
    v.published_date     = $published_date,
    v.created_at         = datetime()
ON MATCH SET
    v.cvss_score         = $cvss_score,
    v.is_exploitable     = $is_exploitable,
    v.has_public_exploit = $has_public_exploit,
    v.patch_available    = $patch_available,
    v.updated_at         = datetime()
RETURN v
"""
# Vulnerability properties:
# cve_id           → "CVE-2024-1234" (unique identifier)
# cvss_score       → 9.8 (0.0 to 10.0, higher = more severe)
# severity         → "CRITICAL", "HIGH", "MEDIUM", "LOW"
# is_exploitable   → true = known to be actively exploitable
# has_public_exploit → true = Metasploit module or PoC exists
# exploit_maturity → "weaponized", "poc", "unproven"
# patch_available  → true = vendor patch exists


CREATE_HAS_VULNERABILITY_RELATIONSHIP = """
MATCH (h:Host {id: $host_id})
MATCH (v:Vulnerability {cve_id: $cve_id})
MERGE (h)-[r:HAS_VULNERABILITY]->(v)
ON CREATE SET
    r.discovered_at  = datetime(),
    r.scanner        = $scanner,
    r.confirmed      = $confirmed
RETURN r
"""


GET_VULNERABILITIES_BY_SEVERITY = """
MATCH (v:Vulnerability)
WHERE v.cvss_score >= $min_score
OPTIONAL MATCH (h:Host)-[:HAS_VULNERABILITY]->(v)
WITH v, count(h) AS affected_hosts
RETURN v, affected_hosts
ORDER BY v.cvss_score DESC, affected_hosts DESC
LIMIT $limit
"""


GET_EXPLOITABLE_VULNERABILITIES = """
MATCH (h:Host)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE v.is_exploitable = true
   OR v.has_public_exploit = true
RETURN
    h.id AS host_id,
    h.hostname AS hostname,
    h.ip_address AS ip_address,
    h.is_internet_facing AS internet_facing,
    v.cve_id AS cve_id,
    v.cvss_score AS cvss_score,
    v.severity AS severity,
    v.has_public_exploit AS has_public_exploit,
    v.exploit_maturity AS exploit_maturity
ORDER BY v.cvss_score DESC, h.is_internet_facing DESC
LIMIT $limit
"""


# ===========================================================================
# USER NODE QUERIES
# ===========================================================================

MERGE_USER = """
MERGE (u:User {id: $id})
ON CREATE SET
    u.username      = $username,
    u.display_name  = $display_name,
    u.is_admin      = $is_admin,
    u.is_service_account = $is_service_account,
    u.department    = $department,
    u.email         = $email,
    u.created_at    = datetime()
ON MATCH SET
    u.is_admin      = $is_admin,
    u.updated_at    = datetime()
RETURN u
"""


CREATE_CAN_ACCESS_RELATIONSHIP = """
MATCH (u:User {id: $user_id})
MATCH (target {id: $target_id})
MERGE (u)-[r:CAN_ACCESS]->(target)
ON CREATE SET
    r.access_level  = $access_level,
    r.created_at    = datetime()
RETURN r
"""
# access_level: "read", "write", "admin", "root"


CREATE_ESCALATES_TO_RELATIONSHIP = """
MATCH (v:Vulnerability {cve_id: $cve_id})
MATCH (u:User {id: $user_id})
MERGE (v)-[r:ESCALATES_TO]->(u)
ON CREATE SET
    r.technique     = $technique,
    r.created_at    = datetime()
RETURN r
"""
# Links a vulnerability to the user privilege level it can achieve
# e.g., CVE-2021-4034 (PwnKit) ESCALATES_TO root user


# ===========================================================================
# DATABASE NODE QUERIES
# ===========================================================================

MERGE_DATABASE = """
MERGE (db:Database {id: $id})
ON CREATE SET
    db.name             = $name,
    db.type             = $type,
    db.version          = $version,
    db.host_id          = $host_id,
    db.port             = $port,
    db.contains_pii     = $contains_pii,
    db.contains_secrets = $contains_secrets,
    db.is_encrypted     = $is_encrypted,
    db.backup_location  = $backup_location,
    db.created_at       = datetime()
ON MATCH SET
    db.contains_pii     = $contains_pii,
    db.updated_at       = datetime()
RETURN db
"""
# type: "postgresql", "mysql", "mongodb", "mssql", "redis"
# contains_pii: true = high priority target (GDPR implications)
# contains_secrets: true = stores API keys, passwords


# ===========================================================================
# FIREWALL NODE QUERIES
# ===========================================================================

MERGE_FIREWALL = """
MERGE (f:Firewall {id: $id})
ON CREATE SET
    f.name          = $name,
    f.rule_action   = $rule_action,
    f.source_ip     = $source_ip,
    f.dest_ip       = $dest_ip,
    f.port          = $port,
    f.protocol      = $protocol,
    f.is_active     = $is_active,
    f.created_at    = datetime()
RETURN f
"""
# rule_action: "ALLOW", "DENY"
# Firewall nodes let you model network segmentation
# A missing DENY rule between subnets = potential attack path


CREATE_CONNECTS_TO_RELATIONSHIP = """
MATCH (source {id: $source_id})
MATCH (target {id: $target_id})
MERGE (source)-[r:CONNECTS_TO]->(target)
ON CREATE SET
    r.port          = $port,
    r.protocol      = $protocol,
    r.is_encrypted  = $is_encrypted,
    r.created_at    = datetime()
RETURN r
"""


# ===========================================================================
# BULK INGESTION QUERIES (for Nmap/Nessus parsing)
# ===========================================================================

BULK_MERGE_HOSTS = """
UNWIND $rows AS row
MERGE (h:Host {id: row.id})
ON CREATE SET
    h.ip_address         = row.ip_address,
    h.hostname           = row.hostname,
    h.os                 = row.os,
    h.subnet             = row.subnet,
    h.is_internet_facing = row.is_internet_facing,
    h.is_critical        = row.is_critical,
    h.created_at         = datetime()
ON MATCH SET
    h.ip_address         = row.ip_address,
    h.hostname           = row.hostname,
    h.updated_at         = datetime()
RETURN count(h) AS merged_count
"""
# UNWIND turns the $rows list into individual rows
# This runs ONE Cypher statement instead of N statements
# For 500 hosts: 1 query vs 500 queries — massive performance gain


BULK_MERGE_VULNERABILITIES = """
UNWIND $rows AS row
MERGE (v:Vulnerability {cve_id: row.cve_id})
ON CREATE SET
    v.id                 = row.id,
    v.description        = row.description,
    v.cvss_score         = row.cvss_score,
    v.severity           = row.severity,
    v.is_exploitable     = row.is_exploitable,
    v.has_public_exploit = row.has_public_exploit,
    v.created_at         = datetime()
ON MATCH SET
    v.cvss_score         = row.cvss_score,
    v.is_exploitable     = row.is_exploitable,
    v.updated_at         = datetime()
RETURN count(v) AS merged_count
"""


BULK_CREATE_HOST_VULNERABILITY_RELS = """
UNWIND $rows AS row
MATCH (h:Host {id: row.host_id})
MATCH (v:Vulnerability {cve_id: row.cve_id})
MERGE (h)-[r:HAS_VULNERABILITY]->(v)
ON CREATE SET
    r.scanner       = row.scanner,
    r.confirmed     = row.confirmed,
    r.discovered_at = datetime()
RETURN count(r) AS merged_count
"""
