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
  }
};
