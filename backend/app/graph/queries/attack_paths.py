"""
Attack Path Queries
===================
All Cypher queries related to finding and analyzing attack paths.

DESIGN PRINCIPLES:
1. All queries are plain string constants — no logic, no f-strings
2. All dynamic values come through $parameters — NEVER string concatenation
   (string concatenation = Cypher injection vulnerability, same as SQL injection)
3. Query names describe what they return, not what they do
4. Comments explain the Cypher for developers unfamiliar with graph query language

CYPHER CRASH COURSE FOR BEGINNERS:
- MATCH      → find patterns in the graph (like SELECT in SQL)
- WHERE      → filter results (like WHERE in SQL)
- RETURN     → specify what to return
- CREATE     → create nodes/relationships (use sparingly, prefer MERGE)
- MERGE      → create if not exists, match if exists (idempotent)
- WITH       → pipe results between clauses (like subqueries)
- UNWIND     → expand a list into rows (like a for-loop)
- $param     → parameter placeholder (ALWAYS use this, never f-strings)
- (n:Label)  → node with label
- [r:TYPE]   → relationship with type
- (a)-[r]->(b) → directed relationship from a to b
- *1..6      → variable-length path, 1 to 6 hops
"""


# ===========================================================================
# ATTACK PATH QUERIES
# ===========================================================================

FIND_ALL_ATTACK_PATHS = """
MATCH path = (source:Host)-[:CONNECTS_TO|RUNS|HAS_VULNERABILITY|CAN_ACCESS*1..$max_hops]->(target)
WHERE source.id = $source_id
  AND (target.id = $target_id OR $target_id IS NULL)
WITH path,
     nodes(path) AS path_nodes,
     relationships(path) AS path_rels,
     length(path) AS hop_count
RETURN
    [n IN path_nodes | {id: n.id, label: labels(n)[0], name: coalesce(n.hostname, n.name, n.cve_id, n.username, 'unknown')}] AS nodes,
    [r IN path_rels | type(r)] AS relationship_types,
    hop_count,
    path
ORDER BY hop_count ASC
LIMIT $limit
"""
# What this does:
# - Finds all paths from a source Host to any target node
# - Traverses CONNECTS_TO, RUNS, HAS_VULNERABILITY, CAN_ACCESS relationships
# - Variable length: 1 to max_hops steps
# - Returns node details, relationship types, and hop count
# - Ordered by shortest path first


FIND_SHORTEST_ATTACK_PATH = """
MATCH (source:Host {id: $source_id}), (target {id: $target_id})
MATCH path = shortestPath((source)-[*1..$max_hops]->(target))
WITH path,
     nodes(path) AS path_nodes,
     relationships(path) AS path_rels
RETURN
    [n IN path_nodes | {
        id: n.id,
        label: labels(n)[0],
        name: coalesce(n.hostname, n.name, n.cve_id, n.username, 'unknown'),
        ip_address: n.ip_address,
        cvss_score: n.cvss_score
    }] AS nodes,
    [r IN path_rels | {type: type(r), properties: properties(r)}] AS relationships,
    length(path) AS hop_count
"""
# Uses Neo4j's built-in shortestPath() function — highly optimized BFS algorithm


FIND_PATHS_THROUGH_VULNERABILITY = """
MATCH (source:Host)-[:CONNECTS_TO|RUNS*1..3]->(intermediate)
     -[:HAS_VULNERABILITY]->(vuln:Vulnerability)
     -[:ESCALATES_TO|CAN_ACCESS*1..3]->(target)
WHERE vuln.cvss_score >= $min_cvss_score
  AND vuln.is_exploitable = true
WITH source, intermediate, vuln, target,
     vuln.cvss_score AS risk_score
RETURN
    source.id AS source_id,
    source.ip_address AS source_ip,
    intermediate.id AS intermediate_id,
    intermediate.hostname AS intermediate_hostname,
    vuln.cve_id AS cve_id,
    vuln.cvss_score AS cvss_score,
    vuln.description AS description,
    vuln.has_public_exploit AS has_public_exploit,
    target.id AS target_id,
    coalesce(target.hostname, target.name) AS target_name
ORDER BY risk_score DESC
LIMIT $limit
"""
# Finds paths that go THROUGH a high-severity exploitable vulnerability
# This is the core "what's the riskiest path?" query


FIND_PATHS_TO_DATABASE = """
MATCH path = (entry:Host)-[*1..$max_hops]->(db:Database)
WHERE entry.is_internet_facing = true
WITH path, db,
     [n IN nodes(path) WHERE n:Vulnerability] AS vulns_on_path,
     length(path) AS hop_count
RETURN
    [n IN nodes(path) | {
        id: n.id,
        label: labels(n)[0],
        name: coalesce(n.hostname, n.name, n.cve_id, n.username, n.id)
    }] AS path_nodes,
    [r IN relationships(path) | type(r)] AS path_relationships,
    db.name AS database_name,
    db.type AS database_type,
    hop_count,
    size(vulns_on_path) AS vulnerability_count,
    [v IN vulns_on_path | v.cve_id] AS cve_ids_on_path
ORDER BY hop_count ASC, vulnerability_count DESC
LIMIT $limit
"""
# Answers the exact question "How can an attacker reach the database?"
# Starts from internet-facing hosts and traverses to any Database node


FIND_CRITICAL_PATHS = """
MATCH path = (source)-[*1..$max_hops]->(target)
WHERE source.is_internet_facing = true
  AND (target:Database OR target:User {is_admin: true})
WITH path,
     [n IN nodes(path) WHERE n:Vulnerability] AS vulns,
     length(path) AS hops
WHERE size(vulns) > 0
WITH path, vulns, hops,
     reduce(score = 0.0, v IN vulns | score + coalesce(v.cvss_score, 0.0)) / size(vulns) AS avg_cvss
RETURN
    [n IN nodes(path) | {id: n.id, label: labels(n)[0], name: coalesce(n.hostname, n.name, n.id)}] AS nodes,
    [r IN relationships(path) | type(r)] AS rels,
    hops,
    size(vulns) AS vuln_count,
    avg_cvss,
    (avg_cvss * 0.6) + ((10.0 - hops) * 0.4) AS composite_risk_score
ORDER BY composite_risk_score DESC
LIMIT $limit
"""
# Composite risk scoring: 60% CVSS weight + 40% path length weight
# Shorter paths with high CVSS = highest risk


FIND_LATERAL_MOVEMENT_PATHS = """
MATCH path = (entry:Host {is_internet_facing: true})-[*1..$max_hops]->(internal:Host)
WHERE internal.is_internet_facing = false
  AND internal.subnet <> entry.subnet
WITH path, internal,
     length(path) AS hops
RETURN
    [n IN nodes(path) | {id: n.id, label: labels(n)[0], ip_address: n.ip_address, subnet: n.subnet}] AS nodes,
    [r IN relationships(path) | type(r)] AS rels,
    hops,
    internal.id AS target_internal_host,
    internal.ip_address AS target_ip
ORDER BY hops ASC
LIMIT $limit
"""
# Finds lateral movement: attacker moving from internet-facing host
# to an internal host in a different subnet


# ===========================================================================
# RISK ANALYSIS QUERIES
# ===========================================================================

GET_HIGHEST_RISK_NODES = """
MATCH (h:Host)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WITH h,
     count(v) AS vuln_count,
     max(v.cvss_score) AS max_cvss,
     avg(v.cvss_score) AS avg_cvss,
     sum(CASE WHEN v.is_exploitable THEN 1 ELSE 0 END) AS exploitable_count
RETURN
    h.id AS host_id,
    h.hostname AS hostname,
    h.ip_address AS ip_address,
    h.is_internet_facing AS internet_facing,
    vuln_count,
    max_cvss,
    round(avg_cvss, 2) AS avg_cvss,
    exploitable_count,
    (max_cvss * 0.5) + (exploitable_count * 1.5) AS risk_score
ORDER BY risk_score DESC
LIMIT $limit
"""


GET_BLAST_RADIUS = """
MATCH (h:Host {id: $host_id})
MATCH path = (h)-[*1..4]->(affected)
WITH DISTINCT affected, labels(affected)[0] AS node_type
RETURN
    node_type,
    count(*) AS count,
    collect(coalesce(affected.hostname, affected.name, affected.id))[..10] AS examples
ORDER BY count DESC
"""
# "If this host is compromised, what else is reachable?"
# Critical for prioritizing which hosts to patch first


GET_NETWORK_ATTACK_SURFACE = """
MATCH (h:Host)
WHERE h.is_internet_facing = true
OPTIONAL MATCH (h)-[:RUNS]->(s:Service)
OPTIONAL MATCH (h)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WITH h,
     count(DISTINCT s) AS service_count,
     count(DISTINCT v) AS vuln_count,
     collect(DISTINCT s.port) AS open_ports
RETURN
    h.id,
    h.hostname,
    h.ip_address,
    service_count,
    vuln_count,
    open_ports
ORDER BY vuln_count DESC
"""
# Maps the entire attack surface: all internet-facing hosts with their
# service count and vulnerability count


# ===========================================================================
# GRAPH STATISTICS QUERIES
# ===========================================================================

GET_GRAPH_SUMMARY = """
MATCH (n)
RETURN labels(n)[0] AS label, count(*) AS count
ORDER BY count DESC
"""

GET_RELATIONSHIP_SUMMARY = """
MATCH ()-[r]->()
RETURN type(r) AS relationship_type, count(*) AS count
ORDER BY count DESC
"""
