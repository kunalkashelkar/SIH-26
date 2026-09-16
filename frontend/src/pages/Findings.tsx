import React, { useState, useEffect } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { findingService, FindingItem } from '../services/api';
import './Findings.css';

export default function Findings() {
  const navigate = useNavigate();
  const { scanId } = useParams();
  const [searchParams] = useSearchParams();
  const queryParam = searchParams.get('q') || '';
  
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState<boolean>(true);
  const [filterText, setFilterText] = useState<string>(queryParam);

  useEffect(() => {
    if (queryParam) {
      setFilterText(queryParam);
    }
  }, [queryParam]);

  useEffect(() => {
    async function loadFindings() {
      try {
        setLoading(true);
        const activeScanId = scanId || localStorage.getItem('last_active_scan_id');
        const data = await findingService.getFindings({ scan_id: activeScanId || undefined });
        setFindings(data);
        setSelectedIds(new Set(data.map(f => f.id)));
      } catch (err) {
        console.warn("Could not fetch real findings:", err);
      } finally {
        setLoading(false);
      }
    }
    loadFindings();
  }, [scanId]);

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return 'Active Scan';
    const d = new Date(dateStr);
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  };

  const displayedFindings = findings.filter(f => 
    !filterText || 
    f.vulnerability_type.toLowerCase().includes(filterText.toLowerCase()) ||
    (f.endpoint_path || '').toLowerCase().includes(filterText.toLowerCase()) ||
    (f.severity || '').toLowerCase().includes(filterText.toLowerCase())
  );

  const toggleSelectAll = () => {
    if (selectedIds.size === displayedFindings.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(displayedFindings.map(f => f.id)));
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
    const dataToExport = displayedFindings.filter(f => selectedIds.has(f.id));
    const blob = new Blob([JSON.stringify(dataToExport.length > 0 ? dataToExport : displayedFindings, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `findings_export_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    a.remove();
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

  const renderPriority = (priority?: string) => {
    return <span className="priority-tag" style={{
      fontSize: '11px',
      fontWeight: 600,
      padding: '2px 6px',
      borderRadius: '4px',
      background: 'rgba(255, 255, 255, 0.08)',
      color: 'var(--color-primary)',
      marginLeft: '6px'
    }}>{priority || 'P2'}</span>;
  };

  const renderStatus = (status: string) => {
    const dotClasses: Record<string, string> = {
      'open': 'dot-open',
      'Open': 'dot-open',
      'verified': 'dot-verified',
      'Verified': 'dot-verified',
      'verified_fixed': 'dot-verified',
      'closed': 'dot-closed',
      'Closed': 'dot-closed'
    };
    return (
      <span className="status-badge">
        <span className={`status-dot ${dotClasses[status] || 'dot-open'}`}></span> {(status || 'OPEN').toUpperCase()}
      </span>
    );
  };

  return (
    <div className="findings-container">
      <div className="findings-header">
        <div>
          <h1 className="findings-title">Findings</h1>
          <p className="findings-subtitle">{displayedFindings.length} verified vulnerabilities detected across your targets.</p>
        </div>
        <div className="findings-actions">
          <button className="btn-secondary" onClick={handleExportJson}>
            <span className="material-symbols-outlined" style={{fontSize: '18px'}}>download</span> Export
          </button>
          <button className="btn-primary" onClick={() => navigate('/scans/new')}>
            <span className="material-symbols-outlined" style={{fontSize: '18px'}}>add</span> New Scan
          </button>
        </div>
      </div>

      <div className="findings-table-card">
        
        {/* Toolbar */}
        <div className="table-toolbar">
          <div className="toolbar-left">
            <div className="search-input-wrapper">
              <span className="material-symbols-outlined search-icon">search</span>
              <input 
                type="text" 
                className="search-input" 
                placeholder="Search vulnerabilities, endpoints, severities..." 
                value={filterText}
                onChange={(e) => setFilterText(e.target.value)}
              />
            </div>
            <button className="btn-filter" onClick={() => setFilterText('')}>
              <span className="material-symbols-outlined" style={{fontSize: '16px'}}>clear_all</span> Reset
            </button>
          </div>
          <div className="toolbar-right">
            <span className="toolbar-right-bold">{selectedIds.size}</span> selected
          </div>
        </div>

        {/* Table */}
        <div className="table-container">
          <table className="findings-table">
            <thead>
              <tr>
                <th style={{width: '40px', textAlign: 'center'}}>
                  <input 
                    type="checkbox" 
                    checked={selectedIds.size === displayedFindings.length && displayedFindings.length > 0} 
                    onChange={toggleSelectAll} 
                  />
                </th>
                <th style={{width: '110px'}}>Severity</th>
                <th style={{width: '24%'}}>Vulnerability</th>
                <th>Endpoint</th>
                <th style={{width: '80px'}}>Method</th>
                <th style={{width: '100px'}}>Status</th>
                <th style={{width: '80px'}}>Risk</th>
                <th style={{width: '120px'}}>Detected At</th>
                <th style={{width: '60px', textAlign: 'right'}}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={9} style={{textAlign: 'center', padding: '32px', color: 'var(--color-on-surface-variant)'}}>
                    Loading confirmed findings...
                  </td>
                </tr>
              ) : displayedFindings.length === 0 ? (
                <tr>
                  <td colSpan={9} style={{textAlign: 'center', padding: '32px', color: 'var(--color-on-surface-variant)'}}>
                    No findings detected for this target scope.
                  </td>
                </tr>
              ) : (
                displayedFindings.map((finding) => {
                  const isSelected = selectedIds.has(finding.id);
                  const method = 'GET';
                  return (
                    <tr key={finding.id} className={isSelected ? 'selected-row' : ''} onClick={() => navigate(`/vulnerabilities/${finding.id}`)} style={{cursor: 'pointer'}}>
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
                        <div style={{fontWeight: 600, color: 'var(--color-on-surface)'}}>{finding.vulnerability_type}</div>
                        {finding.cwe && <div style={{fontSize: '11px', color: 'var(--color-on-surface-variant)', fontFamily: 'monospace'}}>{finding.cwe}</div>}
                      </td>
                      <td>
                        <code className="endpoint-code">{finding.endpoint_path || '/'}</code>
                      </td>
                      <td>
                        <span className="method-badge" style={{fontSize: '10px'}}>{method}</span>
                      </td>
                      <td>{renderStatus(finding.status)}</td>
                      <td>
                        {renderPriority(finding.priority)}
                      </td>
                      <td style={{fontSize: '12px', color: 'var(--color-on-surface-variant)', fontFamily: 'monospace'}}>
                        {formatDate(finding.created_at)}
                      </td>
                      <td style={{textAlign: 'right'}}>
                        <button className="action-btn" title="Investigate Finding" onClick={(e) => { e.stopPropagation(); navigate(`/vulnerabilities/${finding.id}`); }}>
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
          <span className="footer-text">Showing {displayedFindings.length} of {findings.length} findings</span>
        </div>

      </div>
    </div>
  );
}
