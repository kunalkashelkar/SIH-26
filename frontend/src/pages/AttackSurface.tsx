import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './AttackSurface.css';

export default function AttackSurface() {
  const navigate = useNavigate();
  const [selectedNode, setSelectedNode] = useState<string | null>('api-users');
  
  // Highlight effect simulation
  const [highlightPanel, setHighlightPanel] = useState(false);

  const handleNodeClick = (id: string) => {
    setSelectedNode(id);
    setHighlightPanel(true);
    setTimeout(() => setHighlightPanel(false), 300);
  };

  return (
    <div className="attack-surface-container">
      {/* Header */}
      <div className="as-header">
        <div className="as-header-left">
          <div className="as-header-title">
            <h1>example.com</h1>
            <p>Attack Surface Graph</p>
          </div>
          <div className="as-header-divider"></div>
          <div className="as-header-stats">
            <div className="as-stat-box">
              <span className="as-stat-label">Nodes</span>
              <span className="as-stat-value">1,284</span>
            </div>
            <div className="as-stat-box">
              <span className="as-stat-label">Endpoints</span>
              <span className="as-stat-value">342</span>
            </div>
            <div className="as-stat-box">
              <span className="as-stat-label">APIs</span>
              <span className="as-stat-value">86</span>
            </div>
            <div className="as-stat-box">
              <span className="as-stat-label">Parameters</span>
              <span className="as-stat-value">117</span>
            </div>
          </div>
        </div>
        
        <div className="as-header-actions">
          <button className="btn-outline">
            <span className="material-symbols-outlined" style={{fontSize: '16px'}}>filter_list</span> Filter
          </button>
          <button className="btn-outline">
            <span className="material-symbols-outlined" style={{fontSize: '16px'}}>download</span> Export
          </button>
        </div>
      </div>

      <div className="as-main">
        {/* Graph Area */}
        <div className="graph-area">
          <svg className="graph-svg">
            <line x1="20%" y1="50%" x2="40%" y2="30%" stroke="#30363D" strokeWidth="2" />
            <line x1="20%" y1="50%" x2="40%" y2="50%" stroke="#30363D" strokeWidth="2" />
            <line x1="20%" y1="50%" x2="40%" y2="70%" stroke="#30363D" strokeWidth="2" />
            <line x1="40%" y1="30%" x2="60%" y2="20%" stroke="#30363D" strokeWidth="2" />
            <line x1="40%" y1="30%" x2="60%" y2="40%" stroke="#30363D" strokeWidth="2" strokeDasharray="4" />
            <line x1="40%" y1="50%" x2="60%" y2="50%" stroke="#30363D" strokeWidth="2" />
            <line x1="40%" y1="70%" x2="60%" y2="60%" stroke="#30363D" strokeWidth="2" />
            <line x1="40%" y1="70%" x2="60%" y2="80%" stroke="#30363D" strokeWidth="2" />
            <line x1="60%" y1="20%" x2="80%" y2="15%" stroke="#30363D" strokeWidth="2" />
            <line x1="60%" y1="20%" x2="80%" y2="25%" stroke="#30363D" strokeWidth="2" />
          </svg>

          <div className="graph-nodes">
            {/* Root */}
            <div className="graph-node node-root" style={{top: '50%', left: '20%'}}>
              <div className="node-icon-wrapper">
                <span className="material-symbols-outlined text-primary">language</span>
              </div>
              <span className="node-label">example.com</span>
            </div>

            {/* Path Nodes */}
            <div className="graph-node node-path node-path-active" style={{top: '30%', left: '40%'}} onClick={() => handleNodeClick('api')}>
              <div className="node-icon-wrapper">
                <span className="material-symbols-outlined text-tertiary">api</span>
              </div>
              <span className="node-label">/api</span>
            </div>

            <div className="graph-node node-path" style={{top: '50%', left: '40%'}}>
              <div className="node-icon-wrapper">
                <span className="material-symbols-outlined text-muted">login</span>
              </div>
              <span className="node-label">/login</span>
            </div>

            <div className="graph-node node-path" style={{top: '70%', left: '40%'}}>
              <div className="node-icon-wrapper">
                <span className="material-symbols-outlined text-muted">admin_panel_settings</span>
              </div>
              <span className="node-label">/admin</span>
            </div>

            {/* Endpoint Nodes */}
            <div className="graph-node node-vuln" style={{top: '20%', left: '60%'}} onClick={() => handleNodeClick('api-users')}>
              <div className="node-icon-wrapper" style={{animation: selectedNode === 'api-users' ? 'pulse 2s infinite' : ''}}>
                <span className="material-symbols-outlined text-error" style={{fontSize: '16px'}}>bug_report</span>
              </div>
              <span className="node-label">/users</span>
            </div>

            <div className="graph-node node-endpoint" style={{top: '40%', left: '60%'}}>
              <div className="node-icon-wrapper">
                <span className="material-symbols-outlined text-muted" style={{fontSize: '16px'}}>data_object</span>
              </div>
              <span className="node-label" style={{color: 'var(--color-on-surface-variant)'}}>/config</span>
            </div>

            {/* Params */}
            <div className="graph-node node-param" style={{top: '15%', left: '80%'}}>
              <div className="node-icon-wrapper">
                <span style={{fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--color-on-surface-variant)'}}>?</span>
              </div>
              <span className="node-label">id</span>
            </div>

            <div className="graph-node node-param" style={{top: '25%', left: '80%'}}>
              <div className="node-icon-wrapper">
                <span style={{fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--color-on-surface-variant)'}}>?</span>
              </div>
              <span className="node-label">role</span>
            </div>
          </div>

          <div className="graph-legend">
            <span className="legend-title">Legend</span>
            <div className="legend-item">
              <div className="legend-dot dot-target"></div>
              <span>Target</span>
            </div>
            <div className="legend-item">
              <div className="legend-dot dot-active"></div>
              <span>Active Scan</span>
            </div>
            <div className="legend-item">
              <div className="legend-dot dot-risk"></div>
              <span>High Risk</span>
            </div>
          </div>
        </div>

        {/* Details Panel */}
        <div className={`details-panel ${highlightPanel ? 'bg-surface-container-low' : ''}`} style={{backgroundColor: highlightPanel ? 'var(--color-surface-container-low)' : 'var(--color-surface-container-lowest)'}}>
          
          <div className="panel-header">
            <div className="panel-title-row">
              <span className="method-badge">GET</span>
              <h2 className="endpoint-title">/api/users</h2>
            </div>
            <div className="panel-meta-row">
              <span className="risk-badge">
                <span className="material-symbols-outlined" style={{fontSize: '14px'}}>warning</span> HIGH RISK
              </span>
              <span className="meta-time">Discovered 2h ago</span>
            </div>
          </div>

          <div className="panel-content">
            {/* Parameters */}
            <div>
              <h3 className="panel-section-title">Parameters (2)</h3>
              <div className="param-list">
                <div className="param-item">
                  <span className="param-name">?id</span>
                  <span className="param-type">integer</span>
                </div>
                <div className="param-item vuln">
                  <div className="param-name">
                    ?role
                    <span className="material-symbols-outlined text-error" style={{fontSize: '14px'}} title="Vulnerable">bug_report</span>
                  </div>
                  <span className="param-type">string</span>
                </div>
              </div>
            </div>

            {/* Findings */}
            <div>
              <h3 className="panel-section-title">Findings</h3>
              <div className="finding-card">
                <div className="finding-header">
                  <span className="material-symbols-outlined text-error" style={{fontSize: '16px'}}>security</span>
                  <p className="finding-title">IDOR Vulnerability</p>
                </div>
                <div className="finding-body">
                  <p className="finding-desc">Parameter 'role' allows privilege escalation to admin via manipulation.</p>
                  <button className="btn-link" onClick={() => navigate('/findings')}>
                    View Details <span className="material-symbols-outlined" style={{fontSize: '12px'}}>arrow_forward</span>
                  </button>
                </div>
              </div>
            </div>

            {/* History */}
            <div>
              <h3 className="panel-section-title">Scan History</h3>
              <div className="timeline">
                <div className="timeline-event">
                  <div className="timeline-dot timeline-dot-primary"></div>
                  <div className="timeline-content">
                    <p className="timeline-title">Fuzzing Complete</p>
                    <p className="timeline-time">Today, 14:30 UTC</p>
                  </div>
                </div>
                <div className="timeline-event">
                  <div className="timeline-dot timeline-dot-secondary"></div>
                  <div className="timeline-content">
                    <p className="timeline-title muted">Crawling Complete</p>
                    <p className="timeline-time">Today, 14:15 UTC</p>
                  </div>
                </div>
              </div>
            </div>

          </div>
        </div>

      </div>
    </div>
  );
}
