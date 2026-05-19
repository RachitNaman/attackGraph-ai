"""
graph/queries/traversal.py
===========================
Cypher queries specifically for graph traversal operations.

WHY A SEPARATE FILE FROM attack_paths.py?
- attack_paths.py handles PATH FINDING (source → target routing)
- traversal.py handles REACHABILITY (what can be reached, what connects to what)
- Keeps each file focused on one concern — easier to find and maintain

BFS vs DFS — EXPLAINED IN PLAIN ENGLISH:

BFS (Breadth First Search):
    Imagine dropping a stone in a pond.
    The ripples spread outward one ring at a time.
    BFS explores ALL nodes 1 hop away first,
    then ALL nodes 2 hops away, then 3 hops, etc.

    Start → [A, B, C] → [D, E, F, G] → [H, I]
             1 hop          2 hops        3 hops

    USE WHEN: You want the SHORTEST path.
    Neo4j's shortestPath() uses BFS internally.

DFS (Depth First Search):
    Imagine exploring a maze by always going as
    deep as possible before backtracking.
    DFS follows ONE path all the way to the end,
    then backtracks and tries another.

    Start → A → D → H → (dead end, backtrack)
                 → I → (dead end, backtrack)
           → B → E → ...

    USE WHEN: You want to find ALL possible paths,
    including deep ones. Good for privilege escalation chains.

IN ATTACK GRAPH CONTEXT:
    BFS = "What's the quickest way an attacker can reach the DB?"
    DFS = "What are ALL the ways an attacker could escalate privileges?"

Neo4j handles both internally — you just write the Cypher pattern
and Neo4j picks the most efficient algorithm.
"""


# ===========================================================================
# REACHABLE SYSTEMS QUERIES
# ===========================================================================

FIND_REACHABLE_SYSTEMS = """
MATCH (source:Host {id: $host_id})
MATCH path = (source)-[*1..$max_hops]->(reachable)
WHERE reachable.id <> source.id
WITH DISTINCT reachable,
     labels(reachable)[0] AS node_type,
     min(length(path)) AS min_hops
RETURN
    reachable.id AS id,
    node_type AS label,
    coalesce(reachable.hostname, reachable.name, reachable.id) AS name,
    reachable.ip_address AS ip_address,
    reachable.is_critical AS is_critical,
    reachable.cvss_score AS cvss_score,
    min_hops
ORDER BY min_hops ASC, node_type ASC
"""
# What this does:
# Starting from one host, finds EVERY node reachable through
# any combination of relationships up to max_hops deep.
# min_hops tells you the SHORTEST path to each reachable node.
# This answers: "If this host is compromised, what can the attacker touch?"


FIND_REACHABLE_BY_TYPE = """
MATCH (source:Host {id: $host_id})
MATCH path = (source)-[*1..$max_hops]->(reachable)
WHERE labels(reachable)[0] = $node_type
  AND reachable.id <> source.id
WITH DISTINCT reachable,
     min(length(path)) AS min_hops
RETURN
    reachable.id AS id,
    labels(reachable)[0] AS label,
    coalesce(reachable.hostname, reachable.name, reachable.id) AS name,
    reachable.ip_address AS ip_address,
    reachable.is_critical AS is_critical,
    min_hops
ORDER BY min_hops ASC
LIMIT $limit
"""
# Same as above but filtered to a specific node type.
# e.g. node_type="Database" answers: "What databases can this attacker reach?"


FIND_NODES_THAT_CAN_REACH_TARGET = """
MATCH (target {id: $target_id})
MATCH path = (attacker:Host)-[*1..$max_hops]->(target)
WHERE attacker.is_internet_facing = true
WITH DISTINCT attacker,
     min(length(path)) AS min_hops
RETURN
    attacker.id AS id,
    attacker.hostname AS hostname,
    attacker.ip_address AS ip_address,
    attacker.is_internet_facing AS is_internet_facing,
    min_hops
ORDER BY min_hops ASC
"""
# REVERSE traversal — instead of "what can source reach?"
# this answers "what internet-facing hosts can reach this target?"
# Critical for understanding exposure of a specific asset.


# ===========================================================================
# SHORTEST PATH QUERIES
# ===========================================================================

FIND_SHORTEST_PATH_BETWEEN = """
MATCH (source:Host {id: $source_id}), (target {id: $target_id})
MATCH path = shortestPath((source)-[*1..$max_hops]->(target))
WITH path,
     nodes(path) AS path_nodes,
     relationships(path) AS path_rels,
     length(path) AS hop_count
RETURN
    [n IN path_nodes | {
        id:         n.id,
        label:      labels(n)[0],
        name:       coalesce(n.hostname, n.name, n.cve_id, n.username, n.id),
        ip_address: n.ip_address,
        cvss_score: n.cvss_score,
        is_critical: n.is_critical
    }] AS nodes,
    [r IN path_rels | {
        type:       type(r),
        port:       r.port,
        protocol:   r.protocol
    }] AS relationships,
    hop_count
"""
# shortestPath() uses BFS internally — guaranteed to find
# the minimum hop path. If multiple paths have the same
# hop count, it returns one of them arbitrarily.
# Returns null if no path exists — handle this in service layer.


FIND_ALL_SHORTEST_PATHS = """
MATCH (source:Host {id: $source_id}), (target {id: $target_id})
MATCH path = allShortestPaths((source)-[*1..$max_hops]->(target))
WITH path,
     nodes(path) AS path_nodes,
     relationships(path) AS path_rels,
     length(path) AS hop_count
RETURN
    [n IN path_nodes | {
        id:         n.id,
        label:      labels(n)[0],
        name:       coalesce(n.hostname, n.name, n.cve_id, n.username, n.id),
        ip_address: n.ip_address,
        cvss_score: n.cvss_score
    }] AS nodes,
    [r IN path_rels | {
        type:     type(r),
        port:     r.port,
        protocol: r.protocol
    }] AS relationships,
    hop_count
ORDER BY hop_count ASC
LIMIT $limit
"""
# allShortestPaths() finds ALL paths that tie for shortest length.
# Why this matters: if 3 different paths all take 4 hops,
# patching one doesn't help — the attacker uses another.
# You need to see ALL of them to understand full exposure.


# ===========================================================================
# VULNERABLE HOST QUERIES
# ===========================================================================

FIND_VULNERABLE_HOSTS = """
MATCH (h:Host)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE v.cvss_score >= $min_cvss
WITH h,
     collect(DISTINCT {
         cve_id:           v.cve_id,
         cvss_score:       v.cvss_score,
         severity:         v.severity,
         is_exploitable:   v.is_exploitable,
         has_public_exploit: v.has_public_exploit,
         patch_available:  v.patch_available
     }) AS vulnerabilities,
     count(DISTINCT v) AS total_vulns,
     max(v.cvss_score) AS max_cvss,
     sum(CASE WHEN v.is_exploitable THEN 1 ELSE 0 END) AS exploitable_count,
     sum(CASE WHEN v.has_public_exploit THEN 1 ELSE 0 END) AS public_exploit_count
RETURN
    h.id AS host_id,
    h.hostname AS hostname,
    h.ip_address AS ip_address,
    h.os AS os,
    h.subnet AS subnet,
    h.is_internet_facing AS is_internet_facing,
    h.is_critical AS is_critical,
    h.asset_group AS asset_group,
    total_vulns,
    max_cvss,
    exploitable_count,
    public_exploit_count,
    vulnerabilities,
    (max_cvss * 0.5) + (exploitable_count * 1.0) + (public_exploit_count * 1.5)
        + (CASE WHEN h.is_internet_facing THEN 2.0 ELSE 0.0 END)
        + (CASE WHEN h.is_critical THEN 1.5 ELSE 0.0 END) AS risk_score
ORDER BY risk_score DESC
SKIP $skip
LIMIT $limit
"""
# Risk score formula breakdown:
# max_cvss * 0.5           → severity of worst vulnerability
# exploitable_count * 1.0  → each exploitable vuln adds risk
# public_exploit_count * 1.5 → public exploits are extra dangerous
# internet_facing bonus 2.0  → directly reachable by anyone
# critical asset bonus 1.5   → high-value target


FIND_UNPATCHED_CRITICAL_HOSTS = """
MATCH (h:Host)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE v.patch_available = true
  AND v.cvss_score >= $min_cvss
WITH h,
     count(v) AS patchable_vulns,
     collect(v.cve_id)[..5] AS sample_cves,
     max(v.cvss_score) AS max_cvss
RETURN
    h.id AS host_id,
    h.hostname AS hostname,
    h.ip_address AS ip_address,
    h.is_internet_facing AS is_internet_facing,
    h.is_critical AS is_critical,
    patchable_vulns,
    max_cvss,
    sample_cves
ORDER BY patchable_vulns DESC, max_cvss DESC
LIMIT $limit
"""
# Finds hosts with unpatched vulnerabilities where a patch EXISTS.
# These are the lowest-hanging fruit for defenders —
# patch available but not applied = negligence risk.


# ===========================================================================
# BLAST RADIUS QUERIES
# ===========================================================================

FIND_BLAST_RADIUS_DETAIL = """
MATCH (compromised:Host {id: $host_id})
MATCH path = (compromised)-[*1..$max_hops]->(affected)
WHERE affected.id <> compromised.id
WITH affected,
     labels(affected)[0] AS node_type,
     min(length(path)) AS min_hops,
     count(path) AS path_count
WITH
    node_type,
    count(DISTINCT affected) AS affected_count,
    collect(DISTINCT {
        id:       affected.id,
        name:     coalesce(affected.hostname, affected.name, affected.id),
        min_hops: min_hops,
        is_critical: affected.is_critical,
        contains_pii: affected.contains_pii
    })[..10] AS sample_nodes,
    sum(CASE WHEN affected.is_critical THEN 1 ELSE 0 END) AS critical_count,
    sum(CASE WHEN affected.contains_pii THEN 1 ELSE 0 END) AS pii_count
RETURN
    node_type,
    affected_count,
    critical_count,
    pii_count,
    sample_nodes
ORDER BY affected_count DESC
"""
# Detailed blast radius — not just counts but breakdowns
# of critical assets and PII-containing systems affected.
# This is what an incident responder needs immediately
# after a host is compromised.


FIND_BLAST_RADIUS_TIMELINE = """
MATCH (compromised:Host {id: $host_id})
MATCH path = (compromised)-[*1..$max_hops]->(affected)
WHERE affected.id <> compromised.id
WITH affected,
     min(length(path)) AS hop_distance
RETURN
    hop_distance AS hops_from_source,
    count(DISTINCT affected) AS nodes_reachable,
    collect(DISTINCT labels(affected)[0]) AS node_types_at_distance,
    collect(DISTINCT coalesce(affected.hostname, affected.name, affected.id))[..5] AS examples
ORDER BY hop_distance ASC
"""
# Timeline view: at hop 1, attacker can reach X systems.
# At hop 2, Y more. At hop 3, Z more.
# Shows how quickly the blast radius expands —
# helps prioritize network segmentation improvements.


FIND_CRITICAL_ASSETS_IN_BLAST_RADIUS = """
MATCH (compromised:Host {id: $host_id})
MATCH path = (compromised)-[*1..$max_hops]->(critical)
WHERE (critical.is_critical = true OR critical.contains_pii = true)
  AND critical.id <> compromised.id
WITH critical,
     labels(critical)[0] AS node_type,
     min(length(path)) AS min_hops
RETURN
    critical.id AS id,
    node_type AS label,
    coalesce(critical.hostname, critical.name, critical.id) AS name,
    critical.ip_address AS ip_address,
    critical.is_critical AS is_critical,
    critical.contains_pii AS contains_pii,
    min_hops
ORDER BY min_hops ASC, critical.is_critical DESC
"""
# Filters blast radius to ONLY critical or PII assets.
# These are what executives and security teams care about most —
# the difference between "we had an incident" and "we had a breach."


# ===========================================================================
# PRIVILEGE ESCALATION QUERIES
# ===========================================================================

FIND_PRIVILEGE_ESCALATION_CHAINS = """
MATCH path = (start:Host)-[:HAS_VULNERABILITY|RUNS*1..3]->(vuln_or_svc)
             -[:ESCALATES_TO]->(privileged_user:User)
WHERE privileged_user.is_admin = true
WITH path,
     start,
     privileged_user,
     [n IN nodes(path) WHERE n:Vulnerability] AS vulns_used,
     length(path) AS chain_length
RETURN
    start.id AS entry_host_id,
    start.hostname AS entry_hostname,
    start.ip_address AS entry_ip,
    start.is_internet_facing AS entry_internet_facing,
    [n IN nodes(path) | {
        id:    n.id,
        label: labels(n)[0],
        name:  coalesce(n.hostname, n.cve_id, n.username, n.name, n.id),
        cvss_score: n.cvss_score,
        exploit_maturity: n.exploit_maturity
    }] AS chain_nodes,
    [r IN relationships(path) | type(r)] AS chain_relationships,
    privileged_user.username AS target_username,
    privileged_user.is_admin AS is_admin,
    chain_length,
    [v IN vulns_used | {cve_id: v.cve_id, cvss_score: v.cvss_score}] AS exploited_vulnerabilities,
    reduce(score = 0.0, v IN vulns_used | score + coalesce(v.cvss_score, 0.0)) AS total_cvss
ORDER BY total_cvss DESC, chain_length ASC
LIMIT $limit
"""
# Finds complete privilege escalation chains:
# Host → (via vulnerability) → Admin/Root user
# This is the "how does an attacker become admin?" question.
# Ordered by: highest total CVSS first (most dangerous),
# then shortest chain (easiest to execute).


FIND_ESCALATION_TO_ROOT = """
MATCH path = (entry:Host {is_internet_facing: true})
             -[*1..$max_hops]->
             (vuln:Vulnerability {is_exploitable: true})
             -[:ESCALATES_TO]->
             (admin:User {is_admin: true})
WITH path, entry, vuln, admin,
     length(path) AS hops
RETURN
    entry.id AS entry_id,
    entry.hostname AS entry_hostname,
    entry.ip_address AS entry_ip,
    vuln.cve_id AS escalation_cve,
    vuln.cvss_score AS cvss_score,
    vuln.exploit_maturity AS exploit_maturity,
    vuln.has_public_exploit AS has_public_exploit,
    admin.username AS admin_username,
    admin.id AS admin_id,
    [n IN nodes(path) | {
        id: n.id,
        label: labels(n)[0],
        name: coalesce(n.hostname, n.cve_id, n.username, n.id)
    }] AS full_path,
    hops
ORDER BY vuln.cvss_score DESC, hops ASC
LIMIT $limit
"""
# Most dangerous scenario: internet entry point → root/admin
# in one chain. These are the paths that need IMMEDIATE patching.


FIND_SERVICE_ACCOUNT_ESCALATION = """
MATCH (h:Host)-[:RUNS]->(s:Service)
MATCH (s)-[:CAN_ACCESS]->(target)
MATCH (u:User {is_service_account: true})-[:CAN_ACCESS]->(target)
WHERE u.is_admin = false
OPTIONAL MATCH (u)-[:CAN_ACCESS]->(admin_resource)
WHERE admin_resource.is_critical = true
RETURN
    h.id AS host_id,
    h.hostname AS hostname,
    s.name AS service_name,
    s.port AS service_port,
    u.username AS service_account,
    target.id AS shared_target_id,
    coalesce(target.hostname, target.name, target.id) AS shared_target_name,
    labels(target)[0] AS target_type,
    admin_resource.id AS critical_resource_id,
    coalesce(admin_resource.name, admin_resource.hostname) AS critical_resource_name
ORDER BY h.is_internet_facing DESC
LIMIT $limit
"""
# Service account abuse — a common real-world attack vector.
# Service accounts often have excessive permissions.
# This finds cases where compromising a service gives
# access to the same resources as a (more powerful) service account.


FIND_CROSS_SUBNET_ESCALATION = """
MATCH path = (external:Host {is_internet_facing: true})
             -[*1..$max_hops]->
             (internal:Host)
             -[*1..3]->
             (admin:User {is_admin: true})
WHERE internal.subnet <> external.subnet
  AND internal.is_internet_facing = false
WITH path, external, internal, admin,
     length(path) AS hops
RETURN
    external.id AS external_host_id,
    external.ip_address AS external_ip,
    internal.id AS pivot_host_id,
    internal.ip_address AS pivot_ip,
    internal.subnet AS internal_subnet,
    admin.username AS admin_username,
    [n IN nodes(path) | {
        id: n.id,
        label: labels(n)[0],
        name: coalesce(n.hostname, n.name, n.id),
        subnet: n.subnet
    }] AS path_nodes,
    hops
ORDER BY hops ASC
LIMIT $limit
"""
# Cross-subnet privilege escalation:
# attacker enters DMZ → pivots to internal subnet → becomes admin
# This is lateral movement + privilege escalation combined.
# Most severe attack pattern in enterprise environments.
