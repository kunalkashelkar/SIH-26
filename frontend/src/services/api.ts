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
  }
};
