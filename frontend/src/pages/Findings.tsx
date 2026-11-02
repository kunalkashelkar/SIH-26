import React, { useState, useEffect } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { findingService, FindingItem, FindingsMetrics } from '../services/api';
import './Findings.css';

export default function Findings() {
  const navigate = useNavigate();
  const { scanId } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  
  const initialSearch = searchParams.get('q') || '';
  const initialScanId = scanId || searchParams.get('scan_id') || localStorage.getItem('last_active_scan_id') || '';
  
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [metrics, setMetrics] = useState<FindingsMetrics | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState<boolean>(true);
  
  // Filter States
  const [searchText, setSearchText] = useState<string>(initialSearch);
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');
  const [selectedDetectionMethod, setSelectedDetectionMethod] = useState<string>('ALL');
  const [filterScanId, setFilterScanId] = useState<string>(initialScanId);
  
  // Active Drawer Finding
  const [drawerFinding, setDrawerFinding] = useState<FindingItem | null>(null);

  // Fetch metrics and findings
  const loadData = async () => {
    try {
      setLoading(true);
      const activeScan = filterScanId.trim() ? filterScanId.trim() : undefined;
      
      const [fetchedFindings, fetchedMetrics] = await Promise.all([
        findingService.getFindings({
          scan_id: activeScan,
          severity: selectedSeverity !== 'ALL' ? selectedSeverity : undefined,
          status: selectedStatus !== 'ALL' ? selectedStatus : undefined,
          detection_method: selectedDetectionMethod !== 'ALL' ? selectedDetectionMethod : undefined,
          search: searchText.trim() ? searchText.trim() : undefined
        }),
        findingService.getMetrics(activeScan).catch(() => null)
      ]);
      
      setFindings(fetchedFindings);
      if (fetchedMetrics) {
        setMetrics(fetchedMetrics);
      }
      setSelectedIds(new Set(fetchedFindings.map(f => f.id)));
    } catch (err) {
      console.warn("Could not fetch real findings or metrics:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [filterScanId, selectedSeverity, selectedStatus, selectedDetectionMethod]);

  // Debounced search trigger
  useEffect(() => {
    const timer = setTimeout(() => {
      loadData();
    }, 300);
    return () => clearTimeout(timer);
  }, [searchText]);

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return 'Active Scan';
    const d = new Date(dateStr);
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  };

  const toggleSelectAll = () => {
    if (selectedIds.size === findings.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(findings.map(f => f.id)));
    }
  };

  const toggleSelect = (id: string) => {
    const newSet = new Set(selectedIds);
    if (newSet.has(id)) {
      newSet.delete(id);
    } else {
      newSet.add(id);
    }
    setSelectedIds(newSet);
  };

  const handleExportJson = () => {
    const dataToExport = findings.filter(f => selectedIds.has(f.id));
    const blob = new Blob([JSON.stringify(dataToExport.length > 0 ? dataToExport : findings, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `findings_export_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    a.remove();
  };

  const resetFilters = () => {
    setSearchText('');
    setSelectedSeverity('ALL');
    setSelectedStatus('ALL');
    setSelectedDetectionMethod('ALL');
    setFilterScanId('');
    setSearchParams({});
  };

  const renderSeverity = (sev: string) => {
    const s = (sev || 'MEDIUM').toUpperCase();
    const classes: Record<string, string> = {
      'CRITICAL': 'sev-critical',
      'HIGH': 'sev-high',
      'MEDIUM': 'sev-medium',
      'LOW': 'sev-low'
    };
    return <span className={`severity-badge ${classes[s] || 'sev-medium'}`}>{s}</span>;
  };

  const renderStatus = (status: string) => {
    const st = (status || 'OPEN').toLowerCase();
    const dotClasses: Record<string, string> = {
      'open': 'dot-open',
      'verified': 'dot-verified',
      'likely': 'dot-verified',
      'unconfirmed': 'dot-closed',
      'false_positive': 'dot-closed',
      'closed': 'dot-closed'
    };
    return (
      <span className="status-badge">
        <span className={`status-dot ${dotClasses[st] || 'dot-open'}`}></span> {status.toUpperCase()}
      </span>
    );
  };

  // Redact authorization tokens, passwords, cookies in raw evidence
  const redactSensitive = (raw?: string) => {
    if (!raw) return 'No raw payload evidence attached.';
    return raw
      .replace(/(?:Bearer\s+)[A-Za-z0-9\-._~+/]+=*/gi, 'Bearer [REDACTED_TOKEN]')
      .replace(/(?:password|token|secret|access_token|authorization|cookie)([\s:=]+)["']?[^"\s&;]+["']?/gi, '$1[REDACTED]');
  };

  return (
    <div className="findings-container">
      {/* Page Header */}
      <div className="findings-header">
        <div>
          <h1 className="findings-title">Security Findings & Vulnerabilities</h1>
          <p className="findings-subtitle">
            {filterScanId ? `Showing findings isolated to Scan #${filterScanId.slice(0, 8)}` : `Unified attack surface findings across all analyzed web and repository targets.`}
          </p>
        </div>
        <div className="findings-actions">
          {filterScanId && (
            <button className="btn-secondary" onClick={() => { setFilterScanId(''); setSearchParams({}); }}>
              <span className="material-symbols-outlined" style={{fontSize: '18px'}}>clear</span> Show All Scans
            </button>
          )}
          <button className="btn-secondary" onClick={handleExportJson}>
            <span className="material-symbols-outlined" style={{fontSize: '18px'}}>download</span> Export JSON
          </button>
          <button className="btn-primary" onClick={() => navigate('/scans/new')}>
            <span className="material-symbols-outlined" style={{fontSize: '18px'}}>add</span> New Scan
          </button>
        </div>
      </div>

      {/* Real Summary Metrics Bar */}
      {metrics && (
        <div className="findings-metrics-grid">
          <div 
            className={`metric-card ${selectedSeverity === 'ALL' && selectedStatus === 'ALL' ? 'active' : ''}`}
            onClick={() => { setSelectedSeverity('ALL'); setSelectedStatus('ALL'); }}
          >
            <div className="metric-title">Total Findings</div>
            <div className="metric-value" style={{color: 'var(--color-on-surface)'}}>{metrics.total}</div>
          </div>
          <div 
            className={`metric-card ${selectedSeverity === 'CRITICAL' ? 'active' : ''}`}
            onClick={() => setSelectedSeverity(selectedSeverity === 'CRITICAL' ? 'ALL' : 'CRITICAL')}
          >
            <div className="metric-title" style={{color: '#ffdad6'}}>Critical</div>
            <div className="metric-value" style={{color: '#ff5449'}}>{metrics.critical}</div>
          </div>
          <div 
            className={`metric-card ${selectedSeverity === 'HIGH' ? 'active' : ''}`}
            onClick={() => setSelectedSeverity(selectedSeverity === 'HIGH' ? 'ALL' : 'HIGH')}
          >
            <div className="metric-title" style={{color: '#ffd073'}}>High</div>
            <div className="metric-value" style={{color: '#ffba42'}}>{metrics.high}</div>
          </div>
          <div 
            className={`metric-card ${selectedSeverity === 'MEDIUM' ? 'active' : ''}`}
            onClick={() => setSelectedSeverity(selectedSeverity === 'MEDIUM' ? 'ALL' : 'MEDIUM')}
          >
            <div className="metric-title" style={{color: 'var(--color-tertiary)'}}>Medium</div>
            <div className="metric-value" style={{color: 'var(--color-tertiary)'}}>{metrics.medium}</div>
          </div>
          <div 
            className={`metric-card ${selectedSeverity === 'LOW' ? 'active' : ''}`}
            onClick={() => setSelectedSeverity(selectedSeverity === 'LOW' ? 'ALL' : 'LOW')}
          >
            <div className="metric-title" style={{color: 'var(--color-secondary)'}}>Low</div>
            <div className="metric-value" style={{color: 'var(--color-secondary)'}}>{metrics.low}</div>
          </div>
          <div 
            className={`metric-card ${selectedStatus === 'VERIFIED' ? 'active' : ''}`}
            onClick={() => setSelectedStatus(selectedStatus === 'VERIFIED' ? 'ALL' : 'VERIFIED')}
          >
            <div className="metric-title" style={{color: '#4caf50'}}>Confirmed</div>
            <div className="metric-value" style={{color: '#4caf50'}}>{metrics.confirmed}</div>
          </div>
          <div 
            className={`metric-card ${selectedStatus === 'UNCONFIRMED' ? 'active' : ''}`}
            onClick={() => setSelectedStatus(selectedStatus === 'UNCONFIRMED' ? 'ALL' : 'UNCONFIRMED')}
          >
            <div className="metric-title" style={{color: 'var(--color-on-surface-variant)'}}>Unconfirmed</div>
            <div className="metric-value" style={{color: 'var(--color-on-surface-variant)'}}>{metrics.unconfirmed}</div>
          </div>
        </div>
      )}

      {/* Findings Table Card */}
      <div className="findings-table-card">
        
        {/* Search & Selection Toolbar */}
        <div className="table-toolbar">
          <div className="toolbar-left">
            <div className="search-input-wrapper">
              <span className="material-symbols-outlined search-icon">search</span>
              <input 
                type="text" 
                className="search-input" 
                placeholder="Search title, endpoint, CWE, repo file..." 
                value={searchText}
                onChange={(e) => setSearchText(e.target.value)}
              />
            </div>
            <button className="btn-filter" onClick={resetFilters}>
              <span className="material-symbols-outlined" style={{fontSize: '16px'}}>clear_all</span> Reset
            </button>
          </div>
          <div className="toolbar-right">
            <span className="toolbar-right-bold">{selectedIds.size}</span> selected of {findings.length}
          </div>
        </div>

        {/* Multi-Filters Controls Bar */}
        <div className="filters-row">
          <div style={{display: 'flex', alignItems: 'center', gap: '6px'}}>
            <span style={{fontSize: '11px', color: 'var(--color-on-surface-variant)', fontWeight: 600}}>SEVERITY:</span>
            <select 
              className="filter-select"
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          <div style={{display: 'flex', alignItems: 'center', gap: '6px'}}>
            <span style={{fontSize: '11px', color: 'var(--color-on-surface-variant)', fontWeight: 600}}>STATUS:</span>
            <select 
              className="filter-select"
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
            >
              <option value="ALL">All Statuses</option>
              <option value="OPEN">Open</option>
              <option value="VERIFIED">Confirmed / Verified</option>
              <option value="LIKELY">Likely</option>
              <option value="UNCONFIRMED">Unconfirmed</option>
              <option value="FALSE_POSITIVE">False Positive</option>
            </select>
          </div>

          <div style={{display: 'flex', alignItems: 'center', gap: '6px'}}>
            <span style={{fontSize: '11px', color: 'var(--color-on-surface-variant)', fontWeight: 600}}>DETECTION:</span>
            <select 
              className="filter-select"
              value={selectedDetectionMethod}
              onChange={(e) => setSelectedDetectionMethod(e.target.value)}
            >
              <option value="ALL">All Detection Methods</option>
              <option value="STATIC_AST">Static AST (SAST)</option>
              <option value="DYNAMIC_FUZZING">Dynamic Fuzzing</option>
              <option value="RUNTIME_INTERCEPTION">Runtime Interception</option>
            </select>
          </div>

          <div style={{display: 'flex', alignItems: 'center', gap: '6px', marginLeft: 'auto'}}>
            <span style={{fontSize: '11px', color: 'var(--color-on-surface-variant)', fontWeight: 600}}>SCAN ID:</span>
            <input 
              type="text"
              placeholder="Filter by Scan ID..."
              value={filterScanId}
              onChange={(e) => setFilterScanId(e.target.value)}
              className="filter-select font-mono"
              style={{width: '180px'}}
            />
          </div>
        </div>

        {/* Table Body */}
        <div className="table-container">
          <table className="findings-table">
            <thead>
              <tr>
                <th style={{width: '40px', textAlign: 'center'}}>
                  <input 
                    type="checkbox" 
                    checked={selectedIds.size === findings.length && findings.length > 0} 
                    onChange={toggleSelectAll} 
                  />
                </th>
                <th style={{width: '100px'}}>Severity</th>
                <th style={{width: '26%'}}>Vulnerability Title</th>
                <th>Target / Location</th>
                <th style={{width: '80px'}}>Method</th>
                <th style={{width: '110px'}}>Detection</th>
                <th style={{width: '110px'}}>Status</th>
                <th style={{width: '70px'}}>Conf.</th>
                <th style={{width: '110px'}}>Detected</th>
                <th style={{width: '60px', textAlign: 'right'}}>Inspect</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={10} style={{textAlign: 'center', padding: '40px', color: 'var(--color-on-surface-variant)'}}>
                    <span className="material-symbols-outlined spin" style={{fontSize: '24px', verticalAlign: 'middle', marginRight: '8px'}}>sync</span>
                    Loading verified findings from database...
                  </td>
                </tr>
              ) : findings.length === 0 ? (
                <tr>
                  <td colSpan={10} style={{textAlign: 'center', padding: '48px', color: 'var(--color-on-surface-variant)'}}>
                    <span className="material-symbols-outlined" style={{fontSize: '36px', color: 'rgba(255,255,255,0.2)', display: 'block', margin: '0 auto 12px'}}>shield_with_heart</span>
                    <div style={{fontSize: '15px', fontWeight: 600, color: 'var(--color-on-surface)'}}>No Vulnerabilities Discovered</div>
                    <div style={{fontSize: '13px', marginTop: '4px'}}>No findings matching the selected filters were detected in the target scope.</div>
                  </td>
                </tr>
              ) : (
                findings.map((finding) => {
                  const isSelected = selectedIds.has(finding.id);
                  const isRepoSource = !!finding.source_file;
                  
                  return (
                    <tr 
                      key={finding.id} 
                      className={isSelected ? 'selected-row' : ''} 
                      onClick={() => setDrawerFinding(finding)} 
                      style={{cursor: 'pointer'}}
                    >
                      <td style={{textAlign: 'center'}} onClick={(e) => { e.stopPropagation(); toggleSelect(finding.id); }}>
                        <input 
                          type="checkbox" 
                          checked={isSelected} 
                          onChange={() => {}} 
                        />
                      </td>
                      <td>
                        {renderSeverity(finding.severity)}
                      </td>
                      <td className="vuln-name">
                        <div style={{fontWeight: 600, color: 'var(--color-on-surface)'}}>
                          {finding.title || finding.vulnerability_type}
                        </div>
                        <div style={{display: 'flex', alignItems: 'center', gap: '6px', marginTop: '2px'}}>
                          <span style={{fontSize: '11px', color: 'var(--color-on-surface-variant)'}}>{finding.vulnerability_type}</span>
                          {finding.cwe && (
                            <span style={{fontSize: '10px', color: 'var(--color-primary)', fontFamily: 'monospace'}}>
                              {finding.cwe}
                            </span>
                          )}
                        </div>
                      </td>
                      <td>
                        {isRepoSource ? (
                          <span className="source-loc-badge" title={`${finding.source_file}:${finding.source_line_start || 1}`}>
                            <span className="material-symbols-outlined" style={{fontSize: '14px'}}>code</span>
                            <span>{finding.source_file?.split('/').pop()}:{finding.source_line_start || 1}</span>
                          </span>
                        ) : (
                          <code className="endpoint-code">
                            {finding.affected_endpoint || finding.endpoint_path || '/'}
                          </code>
                        )}
                        {finding.parameter_name && (
                          <span style={{fontSize: '11px', color: 'var(--color-on-surface-variant)', marginLeft: '6px'}}>
                            ({finding.parameter_name})
                          </span>
                        )}
                      </td>
                      <td>
                        <span className="method-badge" style={{fontSize: '10px'}}>
                          {finding.http_method || 'GET'}
                        </span>
                      </td>
                      <td>
                        <span className="detection-badge">
                          {finding.detection_method === 'STATIC_AST' ? 'SAST' : 
                           finding.detection_method === 'DYNAMIC_FUZZING' ? 'FUZZER' : 
                           finding.detection_method || 'RUNTIME'}
                        </span>
                      </td>
                      <td>{renderStatus(finding.status)}</td>
                      <td style={{fontSize: '12px', fontWeight: 600, color: 'var(--color-on-surface)'}}>
                        {finding.confidence}%
                      </td>
                      <td style={{fontSize: '11px', color: 'var(--color-on-surface-variant)', fontFamily: 'monospace'}}>
                        {formatDate(finding.created_at)}
                      </td>
                      <td style={{textAlign: 'right'}}>
                        <button 
                          className="action-btn" 
                          title="Inspect Finding Details" 
                          onClick={(e) => { e.stopPropagation(); setDrawerFinding(finding); }}
                        >
                          <span className="material-symbols-outlined" style={{fontSize: '18px'}}>visibility</span>
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Footer */}
        <div className="table-footer">
          <span className="footer-text">Displaying {findings.length} findings from database</span>
        </div>

      </div>

      {/* Slide-over Detail Drawer */}
      {drawerFinding && (
        <div className="detail-drawer-overlay" onClick={() => setDrawerFinding(null)}>
          <div className="detail-drawer" onClick={(e) => e.stopPropagation()}>
            
            <div className="drawer-header">
              <div>
                <div style={{display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px'}}>
                  {renderSeverity(drawerFinding.severity)}
                  <span className="detection-badge">{drawerFinding.detection_method || 'DYNAMIC'}</span>
                  {renderStatus(drawerFinding.status)}
                </div>
                <h2 style={{fontSize: '18px', fontWeight: 700, margin: 0, color: 'var(--color-on-surface)'}}>
                  {drawerFinding.title || drawerFinding.vulnerability_type}
                </h2>
                <div style={{fontSize: '12px', color: 'var(--color-on-surface-variant)', marginTop: '4px'}}>
                  Scan ID: <code className="font-mono">{drawerFinding.scan_id}</code>
                </div>
              </div>
              
              <div style={{display: 'flex', alignItems: 'center', gap: '8px'}}>
                <button 
                  className="btn-secondary" 
                  style={{padding: '6px 10px'}}
                  onClick={() => navigate(`/vulnerabilities/${drawerFinding.id}`)}
                  title="View Dedicated Full Page"
                >
                  <span className="material-symbols-outlined" style={{fontSize: '16px'}}>open_in_new</span>
                </button>
                <button 
                  className="action-btn" 
                  style={{opacity: 1, padding: '6px'}} 
                  onClick={() => setDrawerFinding(null)}
                >
                  <span className="material-symbols-outlined" style={{fontSize: '22px'}}>close</span>
                </button>
              </div>
            </div>

            <div className="drawer-body">
              
              {/* Location Card */}
              <div className="drawer-section">
                <div className="drawer-section-title">
                  <span className="material-symbols-outlined" style={{fontSize: '16px'}}>explore</span>
                  Target Scope & Location
                </div>
                {drawerFinding.source_file ? (
                  <div style={{display: 'flex', flexDirection: 'column', gap: '6px'}}>
                    <div style={{fontSize: '13px', color: 'var(--color-on-surface)'}}>
                      <b>Source File:</b> <code className="font-mono">{drawerFinding.source_file}</code>
                    </div>
                    <div style={{fontSize: '13px', color: 'var(--color-on-surface)'}}>
                      <b>Line Range:</b> Lines {drawerFinding.source_line_start || 1} to {drawerFinding.source_line_end || drawerFinding.source_line_start || 1}
                    </div>
                  </div>
                ) : (
                  <div style={{display: 'flex', flexDirection: 'column', gap: '6px'}}>
                    <div style={{fontSize: '13px', color: 'var(--color-on-surface)'}}>
                      <b>Endpoint:</b> <code className="font-mono">{drawerFinding.affected_endpoint || drawerFinding.endpoint_path || '/'}</code>
                    </div>
                    {drawerFinding.affected_url && (
                      <div style={{fontSize: '12px', color: 'var(--color-on-surface-variant)'}}>
                        <b>Full URL:</b> {drawerFinding.affected_url}
                      </div>
                    )}
                    <div style={{fontSize: '13px', color: 'var(--color-on-surface)'}}>
                      <b>HTTP Method:</b> <span className="method-badge">{drawerFinding.http_method || 'GET'}</span>
                      {drawerFinding.parameter_name && (
                        <span style={{marginLeft: '12px'}}>
                          <b>Vulnerable Parameter:</b> <code>{drawerFinding.parameter_name}</code>
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* Technical Description */}
              <div className="drawer-section">
                <div className="drawer-section-title">
                  <span className="material-symbols-outlined" style={{fontSize: '16px'}}>description</span>
                  Technical Details & Explanation
                </div>
                <p style={{fontSize: '13px', lineHeight: '1.6', color: 'var(--color-on-surface)', margin: 0}}>
                  {drawerFinding.technical_details || drawerFinding.description || 'No detailed technical narrative recorded.'}
                </p>
                {drawerFinding.impact && (
                  <div style={{marginTop: '12px', paddingTop: '10px', borderTop: '1px solid rgba(255,255,255,0.06)'}}>
                    <b style={{fontSize: '12px', color: 'var(--color-on-surface-variant)'}}>Impact Assessment:</b>
                    <p style={{fontSize: '13px', color: 'var(--color-on-surface)', marginTop: '4px', margin: 0}}>
                      {drawerFinding.impact}
                    </p>
                  </div>
                )}
              </div>

              {/* Proof of Exploit / Evidence */}
              <div className="drawer-section">
                <div className="drawer-section-title">
                  <span className="material-symbols-outlined" style={{fontSize: '16px'}}>bug_report</span>
                  Captured Evidence & Proof
                </div>
                {drawerFinding.evidence && drawerFinding.evidence.length > 0 ? (
                  drawerFinding.evidence.map((ev, idx) => (
                    <div key={idx} style={{marginBottom: '10px'}}>
                      <div style={{fontSize: '11px', color: 'var(--color-on-surface-variant)', marginBottom: '4px'}}>
                        Evidence #{idx + 1} ({ev.evidence_type})
                      </div>
                      <div className="code-snippet-box">
                        {redactSensitive(ev.response_body_snippet || ev.request_payload || JSON.stringify(ev.metadata_json, null, 2))}
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="code-snippet-box">
                    {redactSensitive(drawerFinding.technical_details)}
                  </div>
                )}
              </div>

              {/* Remediation & Standards Mapping */}
              <div className="drawer-section">
                <div className="drawer-section-title">
                  <span className="material-symbols-outlined" style={{fontSize: '16px'}}>healing</span>
                  Remediation & Compliance
                </div>
                <div style={{display: 'flex', gap: '12px', marginBottom: '10px'}}>
                  {drawerFinding.cwe && (
                    <div style={{fontSize: '12px', color: 'var(--color-primary)'}}>
                      <b>CWE:</b> {drawerFinding.cwe}
                    </div>
                  )}
                  {drawerFinding.owasp_category && (
                    <div style={{fontSize: '12px', color: 'var(--color-secondary)'}}>
                      <b>OWASP:</b> {drawerFinding.owasp_category}
                    </div>
                  )}
                </div>
                <p style={{fontSize: '13px', lineHeight: '1.5', color: 'var(--color-on-surface)', margin: 0}}>
                  {drawerFinding.remediation || 'Sanitize and validate all user-controlled inputs before processing or rendering.'}
                </p>
              </div>

              {/* Navigation Action */}
              <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '8px'}}>
                <button 
                  className="btn-secondary"
                  onClick={() => navigate(`/scans/${drawerFinding.scan_id}/live`)}
                >
                  <span className="material-symbols-outlined" style={{fontSize: '16px'}}>radar</span>
                  View Associated Scan
                </button>
                <button 
                  className="btn-primary"
                  onClick={() => navigate(`/vulnerabilities/${drawerFinding.id}`)}
                >
                  Open Full Screen Investigation
                  <span className="material-symbols-outlined" style={{fontSize: '16px'}}>arrow_forward</span>
                </button>
              </div>

            </div>

          </div>
        </div>
      )}

    </div>
  );
}
