"""
models/requests/ingestion.py
=============================
Pydantic models for the topology ingestion endpoint.

These mirror the existing MERGE_* query parameters in
graph/queries/assets.py, but with sane defaults so a user submitting
JSON by hand doesn't have to specify every optional field.
"""

from pydantic import BaseModel, Field


class HostIn(BaseModel):
    id: str = Field(..., min_length=1, max_length=100)
    ip_address: str = ""
    hostname: str = ""
    os: str = ""
    os_version: str = ""
    subnet: str = ""
    is_internet_facing: bool = False
    is_critical: bool = False
    asset_group: str = ""


class ServiceIn(BaseModel):
    id: str = Field(..., min_length=1, max_length=100)
    host_id: str
    name: str = ""
    port: int | None = None
    protocol: str = "tcp"
    version: str = ""
    banner: str = ""
    is_encrypted: bool = False


class VulnerabilityIn(BaseModel):
    cve_id: str = Field(..., min_length=1, max_length=50)
    host_id: str
    id: str = ""
    description: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    severity: str = "MEDIUM"
    cwe_id: str = ""
    affected_component: str = ""
    is_exploitable: bool = False
    has_public_exploit: bool = False
    exploit_maturity: str = "unproven"
    patch_available: bool = False
    published_date: str = ""


class TopologyIngestRequest(BaseModel):
    """
    A full or partial network topology submitted by the user.
    All three lists are optional so a user can submit just hosts first,
    then add services/vulnerabilities in a later call.
    """
    hosts: list[HostIn] = Field(default_factory=list, max_length=1000)
    services: list[ServiceIn] = Field(default_factory=list, max_length=2000)
    vulnerabilities: list[VulnerabilityIn] = Field(default_factory=list, max_length=2000)


class IngestResponse(BaseModel):
    hosts_merged: int
    services_merged: int
    vulnerabilities_merged: int
