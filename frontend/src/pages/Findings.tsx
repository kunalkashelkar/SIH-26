import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { scanService, FindingItem } from '../services/api';
import './Findings.css';

export default function Findings() {
  const navigate = useNavigate();
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState<boolean>(true);
  const [filterText, setFilterText] = useState<string>('');

  useEffect(() => {
    async function loadFindings() {
      try {
        setLoading(true);
        // Try fetching active scan if saved
        const activeScanId = localStorage.getItem('last_active_scan_id');
        if (activeScanId) {
          const data = await scanService.getScanFindings(activeScanId);
          if (data && data.length > 0) {
            setFindings(data);
            setSelectedIds(new Set(data.map(f => f.id)));
            setLoading(false);
            return;
          }
        }
      } catch (err) {
        console.warn("Could not fetch real findings, displaying fallback:", err);
      } finally {
        setLoading(false);
      }
    }
    loadFindings();
  }, []);

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

  const renderSeverity = (sev: string) => {
    const classes = {
      'CRITICAL': 'sev-critical',
      'HIGH': 'sev-high',
      'MEDIUM': 'sev-medium',
      'LOW': 'sev-low'
    };
    return <span className={`severity-badge ${classes[sev as keyof typeof classes] || 'sev-medium'}`}>{sev}</span>;
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
      'Verified': 'dot-verified',
      'closed': 'dot-closed',
      'Closed': 'dot-closed'
    };
    return (
      <span className="status-badge">
        <span className={`status-dot ${dotClasses[status] || 'dot-open'}`}></span> {status.toUpperCase()}
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
          <button className="btn-secondary">
            <span className="material-symbols-outlined" style={{fontSize: '18px'}}>download</span> Export
          </button>
          <button className="btn-primary">
            <span className="material-symbols-outlined" style={{fontSize: '18px'}}>add</span> New Finding
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
            <button className="btn-filter">
              <span className="material-symbols-outlined" style={{fontSize: '16px'}}>filter_list</span> Filter
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
                <th style={{width: '48px', textAlign: 'center'}}>
                  <input 
                    type="checkbox" 
                    checked={selectedIds.size === displayedFindings.length && displayedFindings.length > 0} 
                    onChange={toggleSelectAll} 
                  />
                </th>
                <th>Severity & Priority</th>
                <th style={{width: '33%'}}>Vulnerability Name</th>
                <th>Endpoint</th>
                <th style={{textAlign: 'right'}}>Confidence</th>
                <th>Status</th>
                <th style={{width: '48px'}}></th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={7} style={{textAlign: 'center', padding: '32px', color: 'var(--color-on-surface-variant)'}}>
                    Loading confirmed findings...
                  </td>
                </tr>
              ) : displayedFindings.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{textAlign: 'center', padding: '32px', color: 'var(--color-on-surface-variant)'}}>
                    No findings detected yet. Run a scan to discover and validate vulnerabilities.
                  </td>
                </tr>
              ) : (
                displayedFindings.map((finding) => {
                  const isSelected = selectedIds.has(finding.id);
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
                        {renderPriority(finding.priority)}
                      </td>
                      <td className="vuln-name">{finding.vulnerability_type}</td>
                      <td>
                        <code className="endpoint-code">{finding.endpoint_path || '/'}</code>
                      </td>
                      <td style={{textAlign: 'right', color: 'var(--color-on-surface-variant)'}}>{finding.confidence}%</td>
                      <td>{renderStatus(finding.status)}</td>
                      <td style={{textAlign: 'right'}}>
                        <button className="action-btn" onClick={(e) => { e.stopPropagation(); }}>
                          <span className="material-symbols-outlined" style={{fontSize: '18px'}}>more_vert</span>
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
          <span className="footer-text">Showing 1 to 5 of 47 findings</span>
          <div className="pagination">
            <button className="page-btn" disabled>
              <span className="material-symbols-outlined" style={{fontSize: '18px'}}>chevron_left</span>
            </button>
            <button className="page-btn active">1</button>
            <button className="page-btn">2</button>
            <button className="page-btn">3</button>
            <span className="page-dots">...</span>
            <button className="page-btn">10</button>
            <button className="page-btn">
              <span className="material-symbols-outlined" style={{fontSize: '18px'}}>chevron_right</span>
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
