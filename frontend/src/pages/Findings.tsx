import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './Findings.css';

interface Finding {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  name: string;
  endpoint: string;
  confidence: number;
  status: 'Open' | 'Verified' | 'Closed';
}

const mockFindings: Finding[] = [
  { id: '1', severity: 'CRITICAL', name: 'SQL Injection', endpoint: '/api/users', confidence: 96, status: 'Open' },
  { id: '2', severity: 'HIGH', name: 'IDOR', endpoint: '/orders', confidence: 91, status: 'Open' },
  { id: '3', severity: 'HIGH', name: 'XSS', endpoint: '/search', confidence: 87, status: 'Verified' },
  { id: '4', severity: 'MEDIUM', name: 'CORS Misconfiguration', endpoint: '/api', confidence: 82, status: 'Open' },
  { id: '5', severity: 'LOW', name: 'Verbose Error Messages', endpoint: '/auth/login', confidence: 45, status: 'Closed' },
];

export default function Findings() {
  const navigate = useNavigate();
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set(['1', '2', '3', '4']));

  const toggleSelectAll = () => {
    if (selectedIds.size === mockFindings.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(mockFindings.map(f => f.id)));
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
    return <span className={`severity-badge ${classes[sev as keyof typeof classes]}`}>{sev}</span>;
  };

  const renderStatus = (status: string) => {
    const dotClasses = {
      'Open': 'dot-open',
      'Verified': 'dot-verified',
      'Closed': 'dot-closed'
    };
    return (
      <span className="status-badge">
        <span className={`status-dot ${dotClasses[status as keyof typeof dotClasses]}`}></span> {status}
      </span>
    );
  };

  return (
    <div className="findings-container">
      <div className="findings-header">
        <div>
          <h1 className="findings-title">Findings</h1>
          <p className="findings-subtitle">47 vulnerabilities detected across your targets.</p>
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
              <input type="text" className="search-input" placeholder="Search vulnerabilities..." />
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
                    checked={selectedIds.size === mockFindings.length && mockFindings.length > 0} 
                    onChange={toggleSelectAll} 
                  />
                </th>
                <th>Severity</th>
                <th style={{width: '33%'}}>Vulnerability Name</th>
                <th>Endpoint</th>
                <th style={{textAlign: 'right'}}>Confidence</th>
                <th>Status</th>
                <th style={{width: '48px'}}></th>
              </tr>
            </thead>
            <tbody>
              {mockFindings.map((finding) => {
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
                    <td>{renderSeverity(finding.severity)}</td>
                    <td className="vuln-name">{finding.name}</td>
                    <td>
                      <code className="endpoint-code">{finding.endpoint}</code>
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
              })}
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
