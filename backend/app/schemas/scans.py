from pydantic import BaseModel, ConfigDict
from typing import Optional, List
from datetime import datetime

class ScanCreate(BaseModel):
    target_url: str
    target_id: Optional[str] = None
    project_id: Optional[str] = None
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
    scan_id: Optional[str] = None
    status: str
    progress: int
    current_stage: str
    target_url: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)

class ScanListItemResponse(BaseModel):
    id: str
    target_id: str
    target_url: str
    status: str
    current_stage: str
    progress: int
    scan_mode: str
    total_findings: int
    critical_findings: int
    high_findings: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    elapsed_seconds: int = 0
    model_config = ConfigDict(from_attributes=True)

class ParameterResponse(BaseModel):
    id: str
    endpoint_id: str
    name: str
    location: str
    value_type: str
    endpoint_method: str
    endpoint_path: str
    model_config = ConfigDict(from_attributes=True)
    
class AttackSurfaceNodeResponse(BaseModel):
    id: str
    path: str
    method: str
    depth: int
    is_api: bool
    priority_score: int
    parameters: list[str]
    model_config = ConfigDict(from_attributes=True)

class AttackSurfaceResponse(BaseModel):
    nodes: list[AttackSurfaceNodeResponse]
    total_endpoints: int
    total_apis: int
    model_config = ConfigDict(from_attributes=True)

class EvidenceResponse(BaseModel):
    id: str
    evidence_type: Optional[str] = None
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
    priority_reasons: list[str] = []
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

class ScanLogResponse(BaseModel):
    id: str
    scan_id: str
    level: str
    message: str
    timestamp: datetime
    model_config = ConfigDict(from_attributes=True)

class FuzzResultResponse(BaseModel):
    id: str
    scan_id: str
    endpoint_id: Optional[str] = None
    parameter_id: Optional[str] = None
    endpoint_path: Optional[str] = None
    parameter_name: Optional[str] = None
    test_id: Optional[str] = None
    category: str
    payload: str
    status_code: Optional[int] = None
    response_time_ms: float = 0.0
    anomaly_detected: bool = False
    details: Optional[str] = None
    executed_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)

# Project Schemas
class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None

class ProjectResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    created_at: Optional[datetime] = None
    total_targets: int = 0
    total_scans: int = 0
    total_findings: int = 0
    risk_score: float = 0.0
    model_config = ConfigDict(from_attributes=True)

# Target Schemas
class TargetCreate(BaseModel):
    base_url: str
    name: Optional[str] = None
    project_id: Optional[str] = None
    description: Optional[str] = None

class TargetResponse(BaseModel):
    id: str
    project_id: Optional[str] = None
    name: str
    base_url: str
    description: Optional[str] = None
    created_at: Optional[datetime] = None
    last_scanned: Optional[datetime] = None
    total_findings: int = 0
    risk_status: str = "LOW"
    model_config = ConfigDict(from_attributes=True)

# Payload Schemas
class PayloadItemCreate(BaseModel):
    category: str
    payload: str
    indicator: Optional[str] = None
    description: Optional[str] = None

class PayloadItemResponse(BaseModel):
    id: str
    category: str
    payload: str
    indicator: Optional[str] = None
    description: Optional[str] = None
    is_custom: bool = False
    usage_count: int = 0
    success_count: int = 0
    success_rate: float = 0.0
    created_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)

class DashboardMetricsResponse(BaseModel):
    total_scans: int = 0
    completed_scans: int = 0
    running_scans: int = 0
    failed_scans: int = 0
    total_endpoints: int = 0
    total_apis: int = 0
    total_parameters: int = 0
    total_subdomains: int = 0
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    validated_findings: int = 0
    open_findings: int = 0
    resolved_findings: int = 0
    risk_score: float = 0.0
    model_config = ConfigDict(from_attributes=True)
