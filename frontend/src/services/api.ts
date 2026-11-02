const API_BASE = '/api';

export interface ScanRequest {
  discovery_mode?: 'WEBSITE_ONLY' | 'GITHUB_ONLY' | 'HYBRID';
  website_url?: string;
  target_url?: string;
  repository_url?: string;
  repository_branch?: string;
  repository_commit_sha?: string;
  github_token?: string;
  scan_mode?: string;
  max_depth?: number;
  max_requests?: number;
  target_id?: string;
  project_id?: string;
  enable_subdomain_discovery?: boolean;
  enable_directory_discovery?: boolean;
  enable_playwright?: boolean;
  wordlist_limit?: number;
  session_cookie?: string;
  auth_header?: string;
  allowed_domains?: string[];
  excluded_paths?: string[];
}

export interface RepositoryValidationRequest {
  repository_url: string;
  branch?: string;
  commit_sha?: string;
  github_token?: string;
}

export interface RepositoryMetadataResponse {
  valid: boolean;
  provider: string;
  owner: string;
  repository: string;
  visibility: string;
  default_branch: string;
  selected_branch: string;
  resolved_commit_sha: string;
  access_status: string;
  message: string;
  repository_id?: number | null;
  description?: string | null;
  size_kb?: number | null;
  stars_count?: number | null;
  forks_count?: number | null;
  primary_language?: string | null;
  last_updated_at?: string | null;
  available_branches: string[];
}

export interface ScanResponse {
  scan_id: string;
  status: string;
}

export interface ScanStatusResponse {
  scan_id?: string;
  status: string;
  progress: number;
  current_stage: string;
  target_url?: string;
  discovery_mode?: string;
  website_url?: string;
  repository_url?: string;
  repository_branch?: string;
  started_at: string | null;
  completed_at: string | null;
  error_message?: string | null;
  tasks_summary?: {
    pending: number;
    processing: number;
    completed: number;
    failed: number;
    skipped: number;
  };
  module_status?: Record<string, {
    status: string;
    duration_seconds?: number;
    discovered?: number;
    persisted?: number;
    error?: string | null;
    reason?: string | null;
    http_status?: number;
  }>;
  stages?: ScanStageItem[];
}

export interface ScanListItem {
  id: string;
  target_id: string;
  target_url: string;
  status: string;
  current_stage: string;
  progress: number;
  scan_mode: string;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  started_at: string | null;
  completed_at: string | null;
  elapsed_seconds: number;
}

export interface ScanLogItem {
  id: string;
  scan_id: string;
  level: string;
  message: string;
  timestamp: string;
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  metadata: Record<string, any>;
}

export interface GraphEdge {
  source: string;
  target: string;
  relationship: string;
  metadata: Record<string, any>;
}

export interface GraphStats {
  total_nodes: number;
  total_edges: number;
  node_counts_by_type: Record<string, number>;
  density: number;
  is_connected: boolean;
  number_connected_components: number;
  max_depth?: number;
  high_risk_only?: boolean;
  is_truncated?: boolean;
  original_total_nodes?: number;
  original_total_edges?: number;
}

export interface GraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats?: GraphStats;
}

export interface EndpointPriorityResult {
  endpoint_id: string;
  score: number;
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  reasons: string[];
}

export interface EvidenceItem {
  id: string;
  evidence_type?: string;
  baseline_summary?: string;
  test_summary?: string;
  analysis?: string;
  confidence?: string;
  response_body_snippet?: string;
  request_payload?: string;
  metadata_json?: Record<string, any>;
}

export interface ScanStageItem {
  id: string;
  stage_name: string;
  stage_status: string;
  duration: number;
  input_count?: number;
  processed_count?: number;
  successful_count?: number;
  failed_count?: number;
  skipped_count?: number;
  output_count?: number;
  retry_count?: number;
  error_code?: string;
  error_message?: string | null;
  failure_category?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  execution_metadata?: Record<string, any>;
}

export interface FindingsMetrics {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  confirmed: number;
  likely: number;
  unconfirmed: number;
  false_positive: number;
}

export interface FindingItem {
  id: string;
  scan_id: string;
  endpoint_id?: string;
  parameter_id?: string;
  asset_id?: string;
  title?: string;
  endpoint_path?: string;
  parameter_name?: string;
  vulnerability_type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: string;
  priority?: 'P1' | 'P2' | 'P3' | 'P4';
  priority_reasons?: string[];
  status: string;
  description?: string;
  technical_details?: string;
  impact?: string;
  cwe?: string;
  owasp_category?: string;
  remediation?: string;
  affected_url?: string;
  affected_endpoint?: string;
  http_method?: string;
  parameter?: string;
  source_file?: string;
  source_line_start?: number;
  source_line_end?: number;
  detection_method?: string;
  validation_method?: string;
  created_at?: string;
  evidence: EvidenceItem[];
}


export interface FuzzResultItem {
  id: string;
  scan_id: string;
  endpoint_id?: string;
  parameter_id?: string;
  endpoint_path?: string;
  parameter_name?: string;
  test_id?: string;
  category: string;
  payload: string;
  status_code?: number;
  response_time_ms: number;
  anomaly_detected: boolean;
  details?: string;
  executed_at?: string;
}

export interface ScanStatistics {
  scan_id: string;
  target_url: string;
  status: string;
  total_endpoints: number;
  total_apis: number;
  total_parameters: number;
  total_subdomains: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  confirmed_findings: number;
  rejected_anomalies: number;
  verified_fixes: number;
  requests_performed: number;
  scan_duration_seconds: number;
}

export interface ProjectItem {
  id: string;
  name: string;
  description?: string;
  created_at?: string;
  total_targets: number;
  total_scans: number;
  total_findings: number;
  risk_score: number;
}

export interface TargetItem {
  id: string;
  project_id?: string;
  name: string;
  base_url: string;
  description?: string;
  created_at?: string;
  last_scanned?: string | null;
  total_findings: number;
  risk_status: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface PayloadItem {
  id: string;
  category: string;
  payload: string;
  indicator?: string;
  description?: string;
  is_custom: boolean;
  usage_count: number;
  success_count: number;
  success_rate: number;
  created_at?: string;
}

export interface DashboardMetrics {
  total_scans: number;
  completed_scans: number;
  running_scans: number;
  failed_scans: number;
  total_endpoints: number;
  total_apis: number;
  total_parameters: number;
  total_subdomains: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  validated_findings: number;
  open_findings: number;
  resolved_findings: number;
  risk_score: number;
}

export interface SourceEvidenceItem {
  id: string;
  file_path: string;
  line_start?: number;
  line_end?: number;
  snippet?: string;
  ast_node_type?: string;
  rule_name?: string;
  confidence: number;
  verification_status: string;
  metadata_json?: Record<string, any>;
  created_at?: string;
}

export interface RuntimeEvidenceItem {
  id: string;
  url: string;
  method: string;
  response_status?: number;
  response_time_ms: number;
  confidence: number;
  verification_status: string;
  metadata_json?: Record<string, any>;
  created_at?: string;
}

export interface DiscoveredAssetItem {
  id: string;
  scan_id: string;
  asset_type: string;
  identifier: string;
  name?: string;
  path?: string;
  url?: string;
  method?: string;
  discovery_status: string;
  confidence: number;
  metadata_json?: Record<string, any>;
  source_evidences: SourceEvidenceItem[];
  runtime_evidences: RuntimeEvidenceItem[];
  created_at?: string;
}

export interface WebsiteProfileItem {
  id: string;
  scan_id: string;
  base_url: string;
  host?: string;
  title?: string;
  tech_stack: string[];
  sitemap_url?: string;
  robots_txt_present: boolean;
  security_headers?: Record<string, any>;
  created_at?: string;
}

export interface RepositoryProfileItem {
  id: string;
  scan_id: string;
  repo_url: string;
  branch: string;
  commit_sha?: string;
  detected_languages: string[];
  detected_frameworks: string[];
  total_files_analyzed: number;
  total_routes_detected: number;
  created_at?: string;
}

export interface CoverageGapsItem {
  confirmed_discoveries: number;
  candidate_discoveries: number;
  restricted_assets: number;
  failed_attempts: number;
  errors: Array<{
    component: string;
    error_type: string;
    message: string;
    target_url?: string;
    source_file?: string;
    timestamp?: string;
  }>;
  unexplored_states: number;
  remaining_queue_items: number;
  termination_reason?: string | null;
  pages_discovered?: number;
  pages_visited?: number;
  pages_failed?: number;
  endpoints_discovered?: number;
  runtime_observed_endpoints?: number;
  source_only_endpoints?: number;
  matched_endpoints?: number;
  forms_discovered?: number;
  parameters_extracted?: number;
  source_files_inventoried?: number;
  source_files_analyzed?: number;
  source_files_skipped?: number;
  source_files_failed?: number;
  browser_discovery_status?: string;
  correlation_status?: string;
  validation_status?: string;
  coverage_notes?: string[];
}

export interface UnifiedInventoryResponse {
  scan_id: string;
  discovery_mode: string;
  website_profile?: WebsiteProfileItem | null;
  repository_profile?: RepositoryProfileItem | null;
  total_assets: number;
  assets_by_type: Record<string, number>;
  assets_by_status: Record<string, number>;
  assets: DiscoveredAssetItem[];
  coverage_gaps?: CoverageGapsItem | null;
}

// Scans API Service
export const scanService = {
  getDashboardMetrics: async (): Promise<DashboardMetrics> => {
    const res = await fetch(`${API_BASE}/scans/metrics/dashboard`);
    if (!res.ok) throw new Error(`Failed to fetch dashboard metrics: ${res.statusText}`);
    return res.json();
  },

  getScans: async (limit = 50): Promise<ScanListItem[]> => {
    const res = await fetch(`${API_BASE}/scans?limit=${limit}`);
    if (!res.ok) throw new Error(`Failed to fetch scans: ${res.statusText}`);
    return res.json();
  },

  validateRepository: async (data: RepositoryValidationRequest): Promise<RepositoryMetadataResponse> => {
    const res = await fetch(`${API_BASE}/repositories/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error(`Repository validation failed: ${res.statusText}`);
    return res.json();
  },

  createScan: async (data: ScanRequest): Promise<ScanResponse> => {
    const res = await fetch(`${API_BASE}/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error(`Failed to create scan: ${res.statusText}`);
    return res.json();
  },
  
  getScanStatus: async (scanId: string): Promise<ScanStatusResponse> => {
    const res = await fetch(`${API_BASE}/scans/${scanId}`);
    if (!res.ok) throw new Error(`Failed to get scan status: ${res.statusText}`);
    return res.json();
  },

  getScanLogs: async (scanId: string, limit = 100): Promise<ScanLogItem[]> => {
    const res = await fetch(`${API_BASE}/scans/${scanId}/logs?limit=${limit}`);
    if (!res.ok) throw new Error(`Failed to get scan logs: ${res.statusText}`);
    return res.json();
  },

  cancelScan: async (scanId: string): Promise<{ status: string; cancelled: boolean }> => {
    const res = await fetch(`${API_BASE}/scans/${scanId}/cancel`, { method: 'POST' });
    if (!res.ok) throw new Error(`Failed to cancel scan: ${res.statusText}`);
    return res.json();
  },

  getScanInventory: async (scanId: string): Promise<UnifiedInventoryResponse> => {
    const res = await fetch(`${API_BASE}/scans/${scanId}/inventory`);
    if (!res.ok) throw new Error(`Failed to get scan inventory: ${res.statusText}`);
    return res.json();
  },

  getScanGraph: async (scanId: string, depth?: number, highRiskOnly?: boolean): Promise<GraphResponse> => {
    const params = new URLSearchParams();
    if (depth !== undefined) params.append('max_depth', depth.toString());
    if (highRiskOnly !== undefined) params.append('high_risk_only', highRiskOnly.toString());
    const qs = params.toString();
    const url = `${API_BASE}/scans/${scanId}/attack-surface-graph${qs ? `?${qs}` : ''}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Failed to get scan graph: ${res.statusText}`);
    return res.json();
  },

  getScanPriorities: async (scanId: string): Promise<EndpointPriorityResult[]> => {
    const res = await fetch(`${API_BASE}/scans/${scanId}/priorities`);
    if (!res.ok) throw new Error(`Failed to get scan priorities: ${res.statusText}`);
    return res.json();
  },

  getScanFuzzResults: async (scanId: string, limit = 100): Promise<FuzzResultItem[]> => {
    const res = await fetch(`${API_BASE}/scans/${scanId}/fuzz-results?limit=${limit}`);
    if (!res.ok) throw new Error(`Failed to get fuzz results: ${res.statusText}`);
    return res.json();
  },

  getScanFindings: async (scanId: string): Promise<FindingItem[]> => {
    const res = await fetch(`${API_BASE}/scans/${scanId}/findings`);
    if (!res.ok) throw new Error(`Failed to get scan findings: ${res.statusText}`);
    return res.json();
  },

  deleteScan: async (scanId: string): Promise<{ message: string; scan_id: string }> => {
    const res = await fetch(`${API_BASE}/scans/${scanId}`, { method: 'DELETE' });
    if (!res.ok) throw new Error(`Failed to delete scan: ${res.statusText}`);
    return res.json();
  },


  getScanAttackSurface: async (scanId: string): Promise<{ nodes: any[]; total_endpoints: number; total_apis: number }> => {
    const res = await fetch(`${API_BASE}/scans/${scanId}/attack-surface`);
    if (!res.ok) throw new Error(`Failed to get attack surface: ${res.statusText}`);
    return res.json();
  },

  getScanParameters: async (scanId: string): Promise<any[]> => {
    const res = await fetch(`${API_BASE}/scans/${scanId}/parameters`);
    if (!res.ok) throw new Error(`Failed to get scan parameters: ${res.statusText}`);
    return res.json();
  },

  getScanSubdomains: async (scanId: string): Promise<any[]> => {
    const res = await fetch(`${API_BASE}/scans/${scanId}/subdomains`);
    if (!res.ok) throw new Error(`Failed to get scan subdomains: ${res.statusText}`);
    return res.json();
  },

  getScanStatistics: async (scanId: string): Promise<ScanStatistics> => {
    const res = await fetch(`${API_BASE}/scans/${scanId}/statistics`);
    if (!res.ok) throw new Error(`Failed to get scan statistics: ${res.statusText}`);
    return res.json();
  },

  getScanJsonReport: async (scanId: string): Promise<any> => {
    const res = await fetch(`${API_BASE}/reports/scans/${scanId}/json`);
    if (!res.ok) {
      // Fallback
      const fb = await fetch(`${API_BASE}/scans/${scanId}/report/json`);
      if (!fb.ok) throw new Error(`Failed to get JSON report: ${res.statusText}`);
      return fb.json();
    }
    return res.json();
  },

  getScanSarifReport: async (scanId: string): Promise<any> => {
    const res = await fetch(`${API_BASE}/reports/scans/${scanId}/sarif`);
    if (!res.ok) throw new Error(`Failed to get SARIF report: ${res.statusText}`);
    return res.json();
  },

  retryStage: async (scanId: string, stageName: string): Promise<{ message: string; stage_name: string; status: string }> => {
    const res = await fetch(`${API_BASE}/scans/${scanId}/retry-stage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ stage_name: stageName })
    });
    if (!res.ok) throw new Error(`Failed to retry stage: ${res.statusText}`);
    return res.json();
  },

  downloadPdfReportUrl: (scanId: string): string => {
    return `${API_BASE}/reports/scans/${scanId}/pdf`;
  },

  downloadSarifReportUrl: (scanId: string): string => {
    return `${API_BASE}/reports/scans/${scanId}/sarif`;
  },

  downloadJsonReportUrl: (scanId: string): string => {
    return `${API_BASE}/reports/scans/${scanId}/json`;
  }
};

// Findings API Service
export const findingService = {
  getFindings: async (params?: {
    scan_id?: string;
    severity?: string;
    status?: string;
    vulnerability_type?: string;
    detection_method?: string;
    search?: string;
    limit?: number;
    offset?: number;
  }): Promise<FindingItem[]> => {
    const query = new URLSearchParams();
    if (params?.scan_id) query.append('scan_id', params.scan_id);
    if (params?.severity) query.append('severity', params.severity);
    if (params?.status) query.append('status', params.status);
    if (params?.vulnerability_type) query.append('vulnerability_type', params.vulnerability_type);
    if (params?.detection_method) query.append('detection_method', params.detection_method);
    if (params?.search) query.append('search', params.search);
    if (params?.limit) query.append('limit', params.limit.toString());
    if (params?.offset) query.append('offset', params.offset.toString());

    const res = await fetch(`${API_BASE}/findings?${query.toString()}`);
    if (!res.ok) throw new Error(`Failed to get findings: ${res.statusText}`);
    return res.json();
  },

  getMetrics: async (scanId?: string): Promise<FindingsMetrics> => {
    const query = new URLSearchParams();
    if (scanId) query.append('scan_id', scanId);
    const res = await fetch(`${API_BASE}/findings/metrics?${query.toString()}`);
    if (!res.ok) throw new Error(`Failed to get findings metrics: ${res.statusText}`);
    return res.json();
  },

  getFindingById: async (findingId: string): Promise<FindingItem> => {
    const res = await fetch(`${API_BASE}/findings/${findingId}`);
    if (!res.ok) throw new Error(`Failed to get finding: ${res.statusText}`);
    return res.json();
  },

  retestFinding: async (findingId: string): Promise<{ finding_id: string; status: string; retest_id: string; result: string; executed_at: string }> => {
    const res = await fetch(`${API_BASE}/findings/${findingId}/retest`, { method: 'POST' });
    if (!res.ok) throw new Error(`Failed to retest finding: ${res.statusText}`);
    return res.json();
  },

  getFindingRetests: async (findingId: string): Promise<Array<{ id: string; finding_id: string; status: string; result: string; executed_at: string }>> => {
    const res = await fetch(`${API_BASE}/findings/${findingId}/retests`);
    if (!res.ok) throw new Error(`Failed to get finding retests: ${res.statusText}`);
    return res.json();
  }
};

// Targets API Service
export const targetService = {
  getTargets: async (): Promise<TargetItem[]> => {
    const res = await fetch(`${API_BASE}/targets`);
    if (!res.ok) throw new Error(`Failed to fetch targets: ${res.statusText}`);
    return res.json();
  },

  createTarget: async (data: { base_url: string; name?: string; project_id?: string; description?: string }): Promise<TargetItem> => {
    const res = await fetch(`${API_BASE}/targets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error(`Failed to create target: ${res.statusText}`);
    return res.json();
  },

  deleteTarget: async (targetId: string): Promise<void> => {
    const res = await fetch(`${API_BASE}/targets/${targetId}`, { method: 'DELETE' });
    if (!res.ok) throw new Error(`Failed to delete target: ${res.statusText}`);
  }
};

// Projects API Service
export const projectService = {
  getProjects: async (): Promise<ProjectItem[]> => {
    const res = await fetch(`${API_BASE}/projects`);
    if (!res.ok) throw new Error(`Failed to fetch projects: ${res.statusText}`);
    return res.json();
  },

  createProject: async (data: { name: string; description?: string }): Promise<ProjectItem> => {
    const res = await fetch(`${API_BASE}/projects`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error(`Failed to create project: ${res.statusText}`);
    return res.json();
  },

  deleteProject: async (projectId: string): Promise<void> => {
    const res = await fetch(`${API_BASE}/projects/${projectId}`, { method: 'DELETE' });
    if (!res.ok) throw new Error(`Failed to delete project: ${res.statusText}`);
  }
};

// Payloads API Service
export const payloadService = {
  getPayloads: async (category?: string, search?: string): Promise<PayloadItem[]> => {
    const query = new URLSearchParams();
    if (category) query.append('category', category);
    if (search) query.append('search', search);

    const res = await fetch(`${API_BASE}/payloads?${query.toString()}`);
    if (!res.ok) throw new Error(`Failed to fetch payloads: ${res.statusText}`);
    return res.json();
  },

  createPayload: async (data: { category: string; payload: string; indicator?: string; description?: string }): Promise<PayloadItem> => {
    const res = await fetch(`${API_BASE}/payloads`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error(`Failed to create payload: ${res.statusText}`);
    return res.json();
  },

  deletePayload: async (payloadId: string): Promise<void> => {
    const res = await fetch(`${API_BASE}/payloads/${payloadId}`, { method: 'DELETE' });
    if (!res.ok) throw new Error(`Failed to delete payload: ${res.statusText}`);
  }
};

// Machine Learning API Interfaces & Service
export interface MLPredictInput {
  http_method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  endpoint_depth: number;
  endpoint_type: 'API' | 'AUTH' | 'FILE' | 'PAGE' | 'UNKNOWN';
  parameter_count: number;
  query_parameter_count: number;
  body_parameter_count: number;
  authentication_required: number;
  external_exposure: number;
  response_status: number;
  response_size: number;
  response_time: number;
  response_anomaly_score: number;
  graph_degree: number;
  related_endpoint_count: number;
  api_relationship_count: number;
  subdomain_relationship: number;
  vhost_relationship: number;
  previous_vulnerability_evidence: number;
  fuzzing_history: number;
}

export interface MLPredictResponse {
  prediction: number;
  label: string;
  vulnerable_probability: number;
  not_vulnerable_probability: number;
  model_name?: string;
  model_type?: string;
  raw_feature_count: number;
  processed_feature_count: number;
}

export const mlService = {
  getStatus: async () => {
    const res = await fetch(`${API_BASE}/ml/status`);
    if (!res.ok) throw new Error(`Failed to fetch ML status: ${res.statusText}`);
    return res.json();
  },

  predict: async (data: MLPredictInput): Promise<MLPredictResponse> => {
    const res = await fetch(`${API_BASE}/ml/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error(`ML prediction failed: ${res.statusText}`);
    return res.json();
  },

  predictEndpoint: async (endpointId: string): Promise<MLPredictResponse> => {
    const res = await fetch(`${API_BASE}/ml/predict-endpoint/${endpointId}`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error(`Endpoint ML prediction failed: ${res.statusText}`);
    return res.json();
  }
};

// System Health Service
export interface SystemHealth {
  status: string;
  service: string;
  components: {
    backend: string;
    database: string;
    ml_model: string;
    preprocessor: string;
    scanner: string;
  };
}

export const healthService = {
  getHealth: async (): Promise<SystemHealth> => {
    const res = await fetch(`${API_BASE}/health`);
    if (!res.ok) throw new Error(`Health check failed: ${res.statusText}`);
    return res.json();
  }
};

export const repositoryService = {
  validateRepository: scanService.validateRepository,
};
