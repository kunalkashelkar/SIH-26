import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { scanService, FindingItem } from '../services/api';

export default function Dashboard() {
  const navigate = useNavigate();
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [stats, setStats] = useState<any>(null);

  useEffect(() => {
    async function loadDashboard() {
      const activeScanId = localStorage.getItem('last_active_scan_id');
      if (activeScanId) {
        try {
          const [fList, scanStats] = await Promise.all([
            scanService.getScanFindings(activeScanId).catch(() => []),
            scanService.getScanStatistics(activeScanId).catch(() => null)
          ]);
          if (fList && fList.length > 0) setFindings(fList);
          if (scanStats) setStats(scanStats);
        } catch (e) {
          console.warn("Dashboard fetch:", e);
        }
      }
    }
    loadDashboard();
  }, []);

  const critCount = stats ? stats.critical_findings : findings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = stats ? stats.high_findings : findings.filter(f => f.severity === 'HIGH').length;
  const medCount = stats ? stats.medium_findings : findings.filter(f => f.severity === 'MEDIUM').length;
  const lowCount = stats ? stats.low_findings : findings.filter(f => f.severity === 'LOW').length;
  const totalFindings = stats ? stats.total_findings : findings.length;

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-subtitle">Overview of your application's security posture.</p>
        </div>
        <button className="btn-primary-small font-caps" onClick={() => navigate('/scans/new')}>
          <span className="material-symbols-outlined">add</span>
          NEW SCAN
        </button>
      </div>

      <div className="kpi-grid">
        <div className="kpi-card">
          <div className="kpi-header">
            <span className="kpi-label">Active Scans</span>
            <span className="material-symbols-outlined text-primary">manage_search</span>
          </div>
          <div className="kpi-value">{stats ? '1' : '0'}</div>
          <div className="kpi-trend text-secondary">
            <span className="material-symbols-outlined icon-small">check_circle</span>
            <span>{stats ? stats.status : 'System ready'}</span>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-header">
            <span className="kpi-label">Endpoints</span>
            <span className="material-symbols-outlined text-secondary">hub</span>
          </div>
          <div className="kpi-value">{stats ? stats.total_endpoints : 0}</div>
          <div className="kpi-trend text-muted">
            <span className="material-symbols-outlined icon-small">sync</span>
            <span>{stats ? `${stats.total_parameters} parameters` : 'Discovered via crawler'}</span>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-header">
            <span className="kpi-label">Confirmed Vulnerabilities</span>
            <span className="material-symbols-outlined text-error">bug_report</span>
          </div>
          <div className="kpi-value">{totalFindings}</div>
          <div className="kpi-trend text-error">
            <span className="material-symbols-outlined icon-small">warning</span>
            <span>{stats ? `${stats.verified_fixes} verified fixed` : 'Real DB findings'}</span>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-header">
            <span className="kpi-label">Risk Score</span>
            <span className="material-symbols-outlined text-tertiary">health_and_safety</span>
          </div>
          <div className="kpi-value text-tertiary">
            {totalFindings > 0 ? (critCount > 0 ? '8.5' : highCount > 0 ? '6.8' : '4.2') : '0.0'}
            <span className="kpi-subtext">/10</span>
          </div>
          <div className="kpi-progress-bar">
            <div 
              className="kpi-progress-fill bg-tertiary" 
              style={{width: totalFindings > 0 ? (critCount > 0 ? '85%' : highCount > 0 ? '68%' : '42%') : '0%'}}
            ></div>
          </div>
        </div>
      </div>

      <div className="dashboard-grid">
        <div className="dashboard-main-col">
          
          <div className="card">
            <h2 className="card-title">Risk Overview</h2>
            <div className="risk-chart">
              
              <div className="risk-row">
                <div className="risk-label">CRITICAL</div>
                <div className="risk-bar-container">
                  <div className="risk-bar bg-error" style={{width: `${Math.max(critCount * 30, 5)}%`}}></div>
                  <span className="risk-count">{critCount}</span>
                </div>
              </div>
              
              <div className="risk-row">
                <div className="risk-label">HIGH</div>
                <div className="risk-bar-container">
                  <div className="risk-bar bg-tertiary" style={{width: `${Math.max(highCount * 30, 5)}%`}}></div>
                  <span className="risk-count">{highCount}</span>
                </div>
              </div>

              <div className="risk-row">
                <div className="risk-label">MEDIUM</div>
                <div className="risk-bar-container">
                  <div className="risk-bar bg-primary" style={{width: `${Math.max(medCount * 40, 15)}%`}}></div>
                  <span className="risk-count">{medCount}</span>
                </div>
              </div>

              <div className="risk-row">
                <div className="risk-label">LOW</div>
                <div className="risk-bar-container">
                  <div className="risk-bar bg-secondary" style={{width: `${Math.max(lowCount * 30, 5)}%`}}></div>
                  <span className="risk-count">{lowCount}</span>
                </div>
              </div>
              
            </div>
            <div className="card-footer">
              <span>Total Confirmed Findings: {findings.length}</span>
              <span>PostgreSQL-backed</span>
            </div>
          </div>

          <div className="card no-padding">
            <div className="card-header-flex">
              <h2 className="card-title m-0">Recent Scans</h2>
              <button className="btn-link font-caps">
                VIEW ALL <span className="material-symbols-outlined icon-small">arrow_forward</span>
              </button>
            </div>
            
            <div className="table-responsive">
              <table className="data-table">
                <thead>
                  <tr>
                    <th style={{width: '33%'}}>Target</th>
                    <th>Status</th>
                    <th className="text-center">Findings</th>
                    <th>Date</th>
                    <th className="text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td className="font-mono">example.com</td>
                    <td>
                      <span className="status-badge badge-secondary">
                        <span className="status-dot"></span> Completed
                      </span>
                    </td>
                    <td className="text-center font-mono">12</td>
                    <td className="text-muted font-mono-sm">Today, 10:23 AM</td>
                    <td className="text-right">
                      <div className="table-actions">
                        <button className="btn-icon-small" title="View Report" onClick={() => navigate('/scans/demo-1/findings')}><span className="material-symbols-outlined icon-small">visibility</span></button>
                        <button className="btn-icon-small" title="Re-scan" onClick={() => navigate('/scans/new')}><span className="material-symbols-outlined icon-small">replay</span></button>
                      </div>
                    </td>
                  </tr>
                  
                  <tr>
                    <td className="font-mono">api.test.io</td>
                    <td>
                      <span className="status-badge badge-primary">
                        <span className="status-dot pulse"></span> Running (45%)
                      </span>
                    </td>
                    <td className="text-center font-mono">4</td>
                    <td className="text-muted font-mono-sm">Today, 09:15 AM</td>
                    <td className="text-right">
                      <div className="table-actions">
                        <button className="btn-icon-small" title="View Progress" onClick={() => navigate('/scans/demo-2/progress')}><span className="material-symbols-outlined icon-small">visibility</span></button>
                        <button className="btn-icon-small text-error" title="Stop Scan"><span className="material-symbols-outlined icon-small">stop_circle</span></button>
                      </div>
                    </td>
                  </tr>
                  
                  <tr>
                    <td className="font-mono">demo.app</td>
                    <td>
                      <span className="status-badge badge-error">
                        <span className="status-dot"></span> Failed
                      </span>
                    </td>
                    <td className="text-center font-mono text-muted">-</td>
                    <td className="text-muted font-mono-sm">Yesterday</td>
                    <td className="text-right">
                      <div className="table-actions">
                        <button className="btn-icon-small" title="View Logs"><span className="material-symbols-outlined icon-small">subject</span></button>
                        <button className="btn-icon-small" title="Resume/Retry"><span className="material-symbols-outlined icon-small">play_arrow</span></button>
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
          
        </div>
        
        <div className="dashboard-side-col">
          <div className="card full-height flex-col">
            <div className="card-header-basic">
              <h2 className="card-title m-0">Recent Findings</h2>
              <p className="card-subtitle">Latest issues requiring triage.</p>
            </div>
            
            <div className="findings-list">
              {findings.length === 0 ? (
                <div style={{padding: '16px', color: 'var(--color-on-surface-variant)', fontSize: '13px'}}>
                  No findings detected yet. Start a scan to discover vulnerabilities.
                </div>
              ) : (
                findings.slice(0, 4).map((f) => {
                  const borderClass = f.severity === 'CRITICAL' ? 'border-error' : f.severity === 'HIGH' ? 'border-tertiary' : 'border-primary';
                  const badgeClass = f.severity === 'CRITICAL' ? 'badge-error' : f.severity === 'HIGH' ? 'badge-tertiary' : 'badge-primary';
                  return (
                    <div key={f.id} className={`finding-item ${borderClass}`} onClick={() => navigate(`/vulnerabilities/${f.id}`)} style={{cursor: 'pointer'}}>
                      <div className="finding-header">
                        <div className={`severity-badge ${badgeClass}`}>
                          <span className="status-dot"></span> {f.severity}
                        </div>
                        <span className="finding-time">{f.priority || 'P2'}</span>
                      </div>
                      <h3 className="finding-title">{f.vulnerability_type}</h3>
                      <div className="finding-target">
                        <span className="material-symbols-outlined icon-small">public</span> {f.endpoint_path || '/'}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
            
            <div className="card-footer-action">
              <button className="btn-block font-caps" onClick={() => navigate('/findings')}>VIEW ALL FINDINGS</button>
            </div>
          </div>
        </div>
      </div>
      
    </div>
  );
}
