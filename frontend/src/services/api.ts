const API_BASE = '/api';

export interface ScanRequest {
  target_url: string;
  scan_mode?: string;
  max_depth?: number;
  max_requests?: number;
  target_id?: string;
  project_id?: string;
  enable_subdomain_discovery?: boolean;
  enable_directory_discovery?: boolean;
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
  target_url: string;
  started_at: string | null;
  completed_at: string | null;
  error_message?: string | null;
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
}

export interface FindingItem {
  id: string;
  scan_id: string;
  endpoint_id?: string;
  parameter_id?: string;
  endpoint_path?: string;
  parameter_name?: string;
  vulnerability_type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: string;
  priority?: 'P1' | 'P2' | 'P3' | 'P4';
  priority_reasons?: string[];
  status: string;
  description?: string;
  impact?: string;
  cwe?: string;
  owasp_category?: string;
  remediation?: string;
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

  getScanGraph: async (scanId: string): Promise<GraphResponse> => {
    const res = await fetch(`${API_BASE}/scans/${scanId}/graph`);
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
  getFindings: async (params?: { scan_id?: string; severity?: string; status?: string; limit?: number }): Promise<FindingItem[]> => {
    const query = new URLSearchParams();
    if (params?.scan_id) query.append('scan_id', params.scan_id);
    if (params?.severity) query.append('severity', params.severity);
    if (params?.status) query.append('status', params.status);
    if (params?.limit) query.append('limit', params.limit.toString());

    const res = await fetch(`${API_BASE}/findings?${query.toString()}`);
    if (!res.ok) throw new Error(`Failed to get findings: ${res.statusText}`);
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
