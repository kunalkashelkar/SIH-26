import React, { useState } from 'react';
import './Settings.css';

export default function Settings() {
  const [activeTab, setActiveTab] = useState('general');

  return (
    <div className="settings-container">
      <div className="settings-header">
        <h1 className="page-title m-0">Settings</h1>
        <p className="page-subtitle m-0">Manage your project preferences and integrations.</p>
      </div>

      <div className="settings-body">
        {/* Sidebar */}
        <div className="settings-sidebar">
          <button 
            className={`settings-tab ${activeTab === 'general' ? 'active' : ''}`}
            onClick={() => setActiveTab('general')}
          >
            <span className="material-symbols-outlined text-[20px]">tune</span>
            General
          </button>
          <button 
            className={`settings-tab ${activeTab === 'security' ? 'active' : ''}`}
            onClick={() => setActiveTab('security')}
          >
            <span className="material-symbols-outlined text-[20px]">lock</span>
            Security
          </button>
          <button 
            className={`settings-tab ${activeTab === 'notifications' ? 'active' : ''}`}
            onClick={() => setActiveTab('notifications')}
          >
            <span className="material-symbols-outlined text-[20px]">notifications</span>
            Notifications
          </button>
          <button 
            className={`settings-tab ${activeTab === 'integrations' ? 'active' : ''}`}
            onClick={() => setActiveTab('integrations')}
          >
            <span className="material-symbols-outlined text-[20px]">hub</span>
            Integrations
          </button>
        </div>

        {/* Content Area */}
        <div className="settings-content-area">
          {activeTab === 'general' && (
            <div className="settings-panel">
              <div className="settings-card group">
                <div className="settings-card-glow"></div>
                <h2 className="settings-card-title">Project Details</h2>
                <p className="settings-card-subtitle">Basic information about your current workspace.</p>
                
                <div className="flex flex-col gap-6">
                  <div className="form-group">
                    <label className="form-label">Project Name</label>
                    <input type="text" className="form-input" defaultValue="Alpha Sentinel Sec" />
                  </div>
                  
                  <div className="form-group">
                    <label className="form-label">Default Scan Profile</label>
                    <div className="form-select-wrapper">
                      <select className="form-select">
                        <option>Comprehensive OWASP Top 10</option>
                        <option>Lightweight CI/CD Pass</option>
                        <option>Deep Fuzzing Mode</option>
                      </select>
                      <span className="material-symbols-outlined">expand_more</span>
                    </div>
                  </div>

                  <div className="form-group" style={{marginTop: '16px'}}>
                    <label className="form-label" style={{marginBottom: '8px'}}>Interface Theme</label>
                    <div className="theme-grid">
                      <button className="theme-btn active">
                        <div className="theme-preview dark">
                          <div className="preview-line-1"></div>
                          <div className="preview-line-2"></div>
                        </div>
                        <span className="theme-label">System Dark</span>
                      </button>
                      
                      <button className="theme-btn disabled">
                        <div className="theme-preview light">
                          <div className="preview-line-1"></div>
                          <div className="preview-line-2"></div>
                        </div>
                        <span className="theme-label">Light (Pro)</span>
                      </button>

                      <button className="theme-btn disabled">
                        <div className="theme-preview hc">
                          <div className="preview-line-1"></div>
                          <div className="preview-line-2"></div>
                        </div>
                        <span className="theme-label">High Contrast</span>
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              <div className="danger-zone">
                <h3 className="danger-zone-title">Danger Zone</h3>
                <p className="danger-zone-text">Once you delete a project, there is no going back. Please be certain.</p>
                <button className="btn-icon-outline" style={{backgroundColor: 'rgba(255, 180, 171, 0.1)', color: 'var(--color-error)', border: 'none'}}>
                  Delete Project
                </button>
              </div>
            </div>
          )}

          {activeTab === 'security' && (
            <div className="settings-panel">
              <div className="settings-card">
                <div className="flex justify-between items-center mb-6">
                  <div>
                    <h2 className="settings-card-title m-0">API Keys</h2>
                    <p className="settings-card-subtitle m-0 mt-2">Manage keys used for programmatic access to Sentinel.</p>
                  </div>
                  <button className="btn-primary font-caps flex items-center gap-2">
                    <span className="material-symbols-outlined text-[18px]">add</span>
                    Generate New Key
                  </button>
                </div>
                
                <div className="api-key-list">
                  <div className="api-key-item">
                    <div className="api-key-info">
                      <span className="api-key-name">CI/CD Pipeline Access</span>
                      <span className="api-key-date">Created: Oct 24, 2023</span>
                    </div>
                    <div className="api-key-actions">
                      <div className="api-key-value">
                        <span className="dots">••••••••••••••••</span>
                        <span className="suffix">a7f2</span>
                      </div>
                      <button className="btn-icon-transparent"><span className="material-symbols-outlined">content_copy</span></button>
                      <button className="btn-icon-transparent" style={{color: 'var(--color-error)'}}><span className="material-symbols-outlined">delete</span></button>
                    </div>
                  </div>

                  <div className="api-key-item">
                    <div className="api-key-info">
                      <span className="api-key-name">Developer Local Test</span>
                      <span className="api-key-date">Created: Nov 02, 2023</span>
                    </div>
                    <div className="api-key-actions">
                      <div className="api-key-value">
                        <span className="dots">••••••••••••••••</span>
                        <span className="suffix">b9q4</span>
                      </div>
                      <button className="btn-icon-transparent"><span className="material-symbols-outlined">content_copy</span></button>
                      <button className="btn-icon-transparent" style={{color: 'var(--color-error)'}}><span className="material-symbols-outlined">delete</span></button>
                    </div>
                  </div>
                </div>
              </div>

              <div className="settings-card">
                <h2 className="settings-card-title">Allowed Scan Targets</h2>
                <p className="settings-card-subtitle">Restrict scans to specific domains or IP ranges to prevent accidental out-of-scope testing.</p>
                <div style={{backgroundColor: 'var(--color-surface-container)', padding: '16px', borderRadius: '8px'}}>
                  <textarea 
                    className="form-input" 
                    style={{width: '100%', height: '128px', resize: 'none', backgroundColor: 'var(--color-background)', border: 'none'}}
                    defaultValue={"*.internal.acme.corp\napi.acme.corp\n10.0.0.0/8"}
                  />
                  <div className="flex justify-end mt-4">
                    <button className="btn-icon-outline font-caps" style={{padding: '8px 16px', borderRadius: '8px'}}>Save Targets</button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'integrations' && (
            <div className="settings-panel">
              <div className="integration-grid">
                <div className="integration-card">
                  <div className="integration-card-header">
                    <div className="integration-icon">
                      <img src="https://lh3.googleusercontent.com/aida-public/AB6AXuCwPPIuRWSbW_uEZDhdnnvg_eh2WrFqb-3n6Yx1zYeJ-AdhdYtw8Hn1ScGQsX8g8uj1E2RB8TYDZn6px5Q7n8S-l9KYlhcf4Vgl-yYEMQpHDO-_TyrX1o46EY5alOtshg_wm13PcH7DtUkFm7PQo8DxugWWbsv5VdwLruF15OmQycY-ukNx7smPp6kQxqGpWi3oepBdntZuzEP4jRBMLMywSDxZ88S_0b9eHpnYrLIi0s5JMiSmMUVRUg" alt="GitHub" />
                    </div>
                    <div>
                      <h3 className="integration-title">GitHub</h3>
                      <span className="integration-badge">Connected</span>
                    </div>
                  </div>
                  <p className="integration-desc">Sync repositories, trigger scans on pull requests, and report findings directly as commit comments.</p>
                  <div style={{backgroundColor: 'var(--color-surface-container)', padding: '12px', borderRadius: '8px', marginBottom: '24px', display: 'flex', flexDirection: 'column', gap: '4px'}}>
                    <span className="font-mono-sm text-muted">Connected account:</span>
                    <span className="font-body-md text-on-surface">acme-corp-engineering</span>
                  </div>
                  <button className="btn-icon-outline font-caps w-full" style={{borderRadius: '8px', padding: '8px', marginTop: 'auto'}}>Manage Connection</button>
                </div>

                <div className="integration-card">
                  <div className="integration-card-header">
                    <div className="integration-icon">
                      <img src="https://lh3.googleusercontent.com/aida-public/AB6AXuAt8FYq5wRcaFo-8vDRIVoTf69SjJ420-lvZ-QBdAwlGEQa2B0XVdCWdw3KHi4nN94TumVrQVxLWMJ5RwuELLj56OSakigDoAwMTBHEvQN6qnCbbP9tD0kKzsrRsN4r_4KoQGSBXehMomGjpI-n-tVfWtivKxyv8FwaqWYIdcg_Ij1FlO9UB1Qsox0MOiHqr3TM7ylOJ_JAb5092_ee6lFSYrOwrS9gvzcFNC1S3TKa88pjW-vfjdT-lg" alt="GitLab" style={{opacity: 0.6}} />
                    </div>
                    <div>
                      <h3 className="integration-title">GitLab</h3>
                    </div>
                  </div>
                  <p className="integration-desc">Integrate with GitLab CI/CD pipelines and synchronize issue tracking for vulnerabilities.</p>
                  <button className="btn-primary font-caps w-full" style={{borderRadius: '8px', padding: '8px', marginTop: 'auto'}}>Connect GitLab</button>
                </div>

                <div className="integration-card wide">
                  <div className="integration-card-header">
                    <div className="integration-icon">
                      <img src="https://lh3.googleusercontent.com/aida-public/AB6AXuCpzK2_mCNoWorwKIewQMiFUWFuHUNQvsdPFMCfZmSbN3CrJU6eDHp8k72YNSyMyXFNCBJrj1AGqJ9ufsOILmJOlx7S1iBZCmlKCnutNaVW22JNQpalKWYPlL9cWxplSIfsxGVapw6lIle3ZUjrZFBC8RLQsLGJFwkFKhDW7DuhrnQNJ47PZ07xBIVmcJDoYyeZjKQ-AdmBmxEWUzkJLiG6PYKmUnrBw_OBpvOBKw4KahUIgmxSVLsyIQ" alt="Slack" style={{opacity: 0.6}} />
                    </div>
                    <div>
                      <h3 className="integration-title">Slack</h3>
                    </div>
                  </div>
                  <div className="flex flex-col md:flex-row gap-6 items-start md:items-center">
                    <p className="integration-desc m-0">Receive real-time alerts for critical vulnerabilities, scan completion summaries, and system status updates in your team's channels.</p>
                    <button className="btn-primary font-caps" style={{borderRadius: '8px', padding: '8px 24px', whiteSpace: 'nowrap'}}>Connect Workspace</button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'notifications' && (
            <div className="settings-panel">
               <div className="settings-card">
                  <h2 className="settings-card-title">Notification Preferences</h2>
                  <p className="settings-card-subtitle">Control how and when Sentinel alerts you.</p>
                  <p className="text-muted">Notification settings are coming soon.</p>
               </div>
            </div>
          )}

          <div className="settings-ambient-bg"></div>
        </div>
      </div>
    </div>
  );
}
