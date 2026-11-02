from pydantic import BaseModel, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime

class ScanCreate(BaseModel):
    # Discovery Mode: WEBSITE_ONLY, GITHUB_ONLY, REPOSITORY_ONLY, HYBRID
    discovery_mode: Optional[str] = None
    scan_mode: Optional[str] = "Standard"
    
    # Target Inputs
    website_url: Optional[str] = None
    target_url: Optional[str] = None  # Legacy alias for website_url
    repository_url: Optional[str] = None
    repository_branch: Optional[str] = "main"
    repository_commit_sha: Optional[str] = None
    github_token: Optional[str] = None
    
    # Nested repository payload support (Phase 3 contract)
    repository: Optional[Dict[str, Any]] = None
    scan_configuration: Optional[Dict[str, Any]] = None
    
    target_id: Optional[str] = None
    project_id: Optional[str] = None
    
    # Crawler and Discovery parameters
    max_depth: int = 3
    max_requests: int = 10000
    enable_subdomain_discovery: bool = False
    enable_directory_discovery: bool = False
    enable_playwright: bool = True
    wordlist_limit: int = 100
    custom_headers: Optional[dict] = None

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
    target_url: Optional[str] = None
    discovery_mode: Optional[str] = "WEBSITE_ONLY"
    website_url: Optional[str] = None
    repository_url: Optional[str] = None
    repository_branch: Optional[str] = "main"
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    tasks_summary: Optional[Dict[str, int]] = None
    module_status: Optional[Dict[str, Any]] = None
    stages: Optional[List[Dict[str, Any]]] = None
    model_config = ConfigDict(from_attributes=True)

class ScanListItemResponse(BaseModel):
    id: str
    target_id: Optional[str] = None
    target_url: str
    discovery_mode: Optional[str] = "WEBSITE_ONLY"
    website_url: Optional[str] = None
    repository_url: Optional[str] = None
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
    asset_id: Optional[str] = None
    title: Optional[str] = None
    endpoint_path: Optional[str] = None
    parameter_name: Optional[str] = None
    vulnerability_type: str
    severity: str
    confidence: Optional[str] = None
    priority: Optional[str] = "P2"
    priority_reasons: list[str] = []
    status: str
    description: Optional[str] = None
    technical_details: Optional[str] = None
    impact: Optional[str] = None
    cwe: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: Optional[str] = None
    affected_url: Optional[str] = None
    affected_endpoint: Optional[str] = None
    http_method: Optional[str] = "GET"
    parameter: Optional[str] = None
    source_file: Optional[str] = None
    source_line_start: Optional[int] = None
    source_line_end: Optional[int] = None
    detection_method: Optional[str] = None
    validation_method: Optional[str] = None
    first_detected_at: Optional[datetime] = None
    last_updated_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    evidence: list[EvidenceResponse] = []
    model_config = ConfigDict(from_attributes=True)

class FindingsMetricsResponse(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    confirmed: int = 0
    likely: int = 0
    unconfirmed: int = 0
    false_positive: int = 0

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

# ==============================================================================
# Unified Hybrid Discovery Schemas
# ==============================================================================

class SourceEvidenceResponse(BaseModel):
    id: str
    discovery_source: str
    file_path: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    snippet: Optional[str] = None
    confidence: float = 1.0
    verification_status: str
    metadata_json: Optional[dict] = None
    model_config = ConfigDict(from_attributes=True)

class RuntimeEvidenceResponse(BaseModel):
    id: str
    discovery_source: str
    observation_type: str
    url: str
    method: str
    response_status: Optional[int] = None
    response_time_ms: float = 0.0
    confidence: float = 1.0
    verification_status: str
    metadata_json: Optional[dict] = None
    model_config = ConfigDict(from_attributes=True)

class DiscoveredAssetResponse(BaseModel):
    id: str
    scan_id: str
    asset_type: str
    identifier: str
    name: Optional[str] = None
    path: Optional[str] = None
    url: Optional[str] = None
    method: Optional[str] = "GET"
    discovery_status: str
    confidence: float = 1.0
    metadata_json: Optional[dict] = None
    source_evidences: List[SourceEvidenceResponse] = []
    runtime_evidences: List[RuntimeEvidenceResponse] = []
    created_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)

class WebsiteProfileResponse(BaseModel):
    id: str
    scan_id: str
    base_url: str
    host: Optional[str] = None
    title: Optional[str] = None
    tech_stack: List[str] = []
    sitemap_url: Optional[str] = None
    robots_txt_present: bool = False
    security_headers: Optional[dict] = None
    created_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)

class RepositoryProfileResponse(BaseModel):
    id: str
    scan_id: str
    repo_url: str
    branch: str = "main"
    commit_sha: Optional[str] = None
    detected_languages: List[str] = []
    detected_frameworks: List[str] = []
    total_files_analyzed: int = 0
    total_routes_detected: int = 0
    created_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)

class CoverageGapsResponse(BaseModel):
    confirmed_discoveries: int = 0
    candidate_discoveries: int = 0
    restricted_assets: int = 0
    failed_attempts: int = 0
    errors: List[dict] = []
    unexplored_states: int = 0
    remaining_queue_items: int = 0
    termination_reason: Optional[str] = None
    # Section 13 - Evidence-Based Coverage Metrics
    pages_discovered: int = 0
    pages_visited: int = 0
    pages_failed: int = 0
    endpoints_discovered: int = 0
    runtime_observed_endpoints: int = 0
    source_only_endpoints: int = 0
    matched_endpoints: int = 0
    forms_discovered: int = 0
    parameters_extracted: int = 0
    source_files_inventoried: int = 0
    source_files_analyzed: int = 0
    source_files_skipped: int = 0
    source_files_failed: int = 0
    browser_discovery_status: str = "NOT_PERFORMED"
    correlation_status: str = "NOT_PERFORMED"
    validation_status: str = "NOT_PERFORMED"
    coverage_notes: List[str] = []
    model_config = ConfigDict(from_attributes=True)

class UnifiedInventoryResponse(BaseModel):
    scan_id: str
    discovery_mode: str
    website_profile: Optional[WebsiteProfileResponse] = None
    repository_profile: Optional[RepositoryProfileResponse] = None
    total_assets: int = 0
    assets_by_type: dict = {}
    assets_by_status: dict = {}
    assets: List[DiscoveredAssetResponse] = []
    coverage_gaps: Optional[CoverageGapsResponse] = None
    model_config = ConfigDict(from_attributes=True)
