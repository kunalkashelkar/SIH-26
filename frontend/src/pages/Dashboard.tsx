import React from 'react';
import { useNavigate } from 'react-router-dom';

export default function Dashboard() {
  const navigate = useNavigate();

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
            <span className="kpi-label">Total Scans</span>
            <span className="material-symbols-outlined text-primary">manage_search</span>
          </div>
          <div className="kpi-value">24</div>
          <div className="kpi-trend text-secondary">
            <span className="material-symbols-outlined icon-small">arrow_upward</span>
            <span>+3 this week</span>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-header">
            <span className="kpi-label">Endpoints</span>
            <span className="material-symbols-outlined text-secondary">hub</span>
          </div>
          <div className="kpi-value">1,284</div>
          <div className="kpi-trend text-muted">
            <span className="material-symbols-outlined icon-small">sync</span>
            <span>Last update 2h ago</span>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-header">
            <span className="kpi-label">Vulnerabilities</span>
            <span className="material-symbols-outlined text-error">bug_report</span>
          </div>
          <div className="kpi-value">47</div>
          <div className="kpi-trend text-error">
            <span className="material-symbols-outlined icon-small">warning</span>
            <span>12 require attention</span>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-header">
            <span className="kpi-label">Risk Score</span>
            <span className="material-symbols-outlined text-tertiary">health_and_safety</span>
          </div>
          <div className="kpi-value text-tertiary">6.8<span className="kpi-subtext">/10</span></div>
          <div className="kpi-progress-bar">
            <div className="kpi-progress-fill bg-tertiary" style={{width: '68%'}}></div>
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
                  <div className="risk-bar bg-error" style={{width: '15%'}}></div>
                  <span className="risk-count">3</span>
                </div>
              </div>
              
              <div className="risk-row">
                <div className="risk-label">HIGH</div>
                <div className="risk-bar-container">
                  <div className="risk-bar bg-tertiary" style={{width: '45%'}}></div>
                  <span className="risk-count">12</span>
                </div>
              </div>

              <div className="risk-row">
                <div className="risk-label">MEDIUM</div>
                <div className="risk-bar-container">
                  <div className="risk-bar bg-primary" style={{width: '60%'}}></div>
                  <span className="risk-count">18</span>
                </div>
              </div>

              <div className="risk-row">
                <div className="risk-label">LOW</div>
                <div className="risk-bar-container">
                  <div className="risk-bar bg-secondary" style={{width: '30%'}}></div>
                  <span className="risk-count">14</span>
                </div>
              </div>
              
            </div>
            <div className="card-footer">
              <span>Total Findings: 47</span>
              <span>Last 30 days trend</span>
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
              
              <div className="finding-item border-error">
                <div className="finding-header">
                  <div className="severity-badge badge-error">
                    <span className="status-dot"></span> CRITICAL
                  </div>
                  <span className="finding-time">2m ago</span>
                </div>
                <h3 className="finding-title">SQL Injection in Login Form</h3>
                <div className="finding-target">
                  <span className="material-symbols-outlined icon-small">public</span> example.com
                </div>
              </div>
              
              <div className="finding-item border-tertiary">
                <div className="finding-header">
                  <div className="severity-badge badge-tertiary">
                    <span className="status-dot"></span> HIGH
                  </div>
                  <span className="finding-time">1h ago</span>
                </div>
                <h3 className="finding-title">IDOR on User Profile Endpoint</h3>
                <div className="finding-target">
                  <span className="material-symbols-outlined icon-small">api</span> api.test.io
                </div>
              </div>
              
              <div className="finding-item border-tertiary">
                <div className="finding-header">
                  <div className="severity-badge badge-tertiary">
                    <span className="status-dot"></span> HIGH
                  </div>
                  <span className="finding-time">3h ago</span>
                </div>
                <h3 className="finding-title">Reflected XSS in Search Query</h3>
                <div className="finding-target">
                  <span className="material-symbols-outlined icon-small">public</span> example.com
                </div>
              </div>
              
              <div className="finding-item border-primary">
                <div className="finding-header">
                  <div className="severity-badge badge-primary">
                    <span className="status-dot"></span> MEDIUM
                  </div>
                  <span className="finding-time">Yesterday</span>
                </div>
                <h3 className="finding-title">Missing Security Headers</h3>
                <div className="finding-target">
                  <span className="material-symbols-outlined icon-small">public</span> example.com
                </div>
              </div>
              
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
