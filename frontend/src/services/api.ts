const API_BASE = '/api';

export interface ScanRequest {
  target_url: string;
  scan_mode: string;
  max_depth: number;
  max_requests: number;
}

export interface ScanResponse {
  scan_id: string;
  status: string;
}

export interface ScanStatusResponse {
  status: string;
  progress: number;
  current_stage: string;
  target_url: string;
  started_at: string | null;
  completed_at: string | null;
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
  evidence_type: string;
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
  status: string;
  description?: string;
  impact?: string;
  cwe?: string;
  owasp_category?: string;
  remediation?: string;
  created_at?: string;
  evidence: EvidenceItem[];
}

export const scanService = {
  createScan: async (data: ScanRequest): Promise<ScanResponse> => {
    const response = await fetch(`${API_BASE}/scans`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    });
    if (!response.ok) {
      throw new Error(`Failed to create scan: ${response.statusText}`);
    }
    return response.json();
  },
  
  getScanStatus: async (scanId: string): Promise<ScanStatusResponse> => {
    const response = await fetch(`${API_BASE}/scans/${scanId}`);
    if (!response.ok) {
      throw new Error(`Failed to get scan status: ${response.statusText}`);
    }
    return response.json();
  },

  getScanGraph: async (scanId: string): Promise<GraphResponse> => {
    const response = await fetch(`${API_BASE}/scans/${scanId}/graph`);
    if (!response.ok) {
      throw new Error(`Failed to get scan graph: ${response.statusText}`);
    }
    return response.json();
  },

  getScanPriorities: async (scanId: string): Promise<EndpointPriorityResult[]> => {
    const response = await fetch(`${API_BASE}/scans/${scanId}/priorities`);
    if (!response.ok) {
      throw new Error(`Failed to get scan priorities: ${response.statusText}`);
    }
    return response.json();
  },

  getScanFindings: async (scanId: string): Promise<FindingItem[]> => {
    const response = await fetch(`${API_BASE}/scans/${scanId}/findings`);
    if (!response.ok) {
      throw new Error(`Failed to get scan findings: ${response.statusText}`);
    }
    return response.json();
  },

  getFindingById: async (findingId: string): Promise<FindingItem> => {
    const response = await fetch(`${API_BASE}/findings/${findingId}`);
    if (!response.ok) {
      throw new Error(`Failed to get finding: ${response.statusText}`);
    }
    return response.json();
  },

  retestFinding: async (findingId: string): Promise<{ finding_id: string; status: string; retest_id: string; result: string; executed_at: string }> => {
    const response = await fetch(`${API_BASE}/findings/${findingId}/retest`, {
      method: 'POST',
    });
    if (!response.ok) {
      throw new Error(`Failed to retest finding: ${response.statusText}`);
    }
    return response.json();
  },

  getFindingRetests: async (findingId: string): Promise<Array<{ id: string; finding_id: string; status: string; result: string; executed_at: string }>> => {
    const response = await fetch(`${API_BASE}/findings/${findingId}/retests`);
    if (!response.ok) {
      throw new Error(`Failed to get finding retests: ${response.statusText}`);
    }
    return response.json();
  },

  getScanStatistics: async (scanId: string): Promise<any> => {
    const response = await fetch(`${API_BASE}/scans/${scanId}/statistics`);
    if (!response.ok) {
      throw new Error(`Failed to get scan statistics: ${response.statusText}`);
    }
    return response.json();
  },

  getScanJsonReport: async (scanId: string): Promise<any> => {
    const response = await fetch(`${API_BASE}/scans/${scanId}/report/json`);
    if (!response.ok) {
      throw new Error(`Failed to get JSON report: ${response.statusText}`);
    }
    return response.json();
  },

  downloadPdfReportUrl: (scanId: string): string => {
    return `${API_BASE}/scans/${scanId}/report/pdf`;
  }
};
