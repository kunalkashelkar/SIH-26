from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime

class ScanCreate(BaseModel):
    target_url: str
    scan_mode: str = "Standard"
    max_depth: int = 3
    max_requests: int = 10000
    enable_subdomain_discovery: bool = False
    enable_directory_discovery: bool = False
    wordlist_limit: int = 100

class SubdomainResponse(BaseModel):
    id: str
    domain: str
    ip_address: Optional[str] = None
    is_alive: bool
    model_config = ConfigDict(from_attributes=True)

class ScanResponse(BaseModel):
    scan_id: str
    status: str

class ScanStatusResponse(BaseModel):
    status: str
    progress: int
    current_stage: str
    target_url: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)

class ParameterResponse(BaseModel):
    id: str
    endpoint_id: str
    name: str
    location: str
    value_type: str
    endpoint_method: str
    endpoint_path: str
    
class AttackSurfaceNodeResponse(BaseModel):
    id: str
    path: str
    method: str
    depth: int
    is_api: bool
    priority_score: int
    parameters: list[str]

class AttackSurfaceResponse(BaseModel):
    nodes: list[AttackSurfaceNodeResponse]
    total_endpoints: int
    total_apis: int
    model_config = ConfigDict(from_attributes=True)

class EvidenceResponse(BaseModel):
    id: str
    evidence_type: str
    baseline_summary: Optional[str] = None
    test_summary: Optional[str] = None
    analysis: Optional[str] = None
    confidence: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)

class FindingResponse(BaseModel):
    id: str
    scan_id: str
    endpoint_id: Optional[str] = None
    parameter_id: Optional[str] = None
    endpoint_path: Optional[str] = None
    parameter_name: Optional[str] = None
    vulnerability_type: str
    severity: str
    confidence: Optional[str] = None
    priority: Optional[str] = "P2"
    status: str
    description: Optional[str] = None
    impact: Optional[str] = None
    cwe: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: Optional[str] = None
    created_at: Optional[datetime] = None
    evidence: list[EvidenceResponse] = []
    model_config = ConfigDict(from_attributes=True)

class RetestResponse(BaseModel):
    id: str
    finding_id: str
    status: str
    result: Optional[str] = None
    executed_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)

class ScanStatisticsResponse(BaseModel):
    scan_id: str
    target_url: str
    status: str
    total_endpoints: int
    total_apis: int
    total_parameters: int
    total_subdomains: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    confirmed_findings: int
    rejected_anomalies: int
    verified_fixes: int
    requests_performed: int
    scan_duration_seconds: int
    model_config = ConfigDict(from_attributes=True)

