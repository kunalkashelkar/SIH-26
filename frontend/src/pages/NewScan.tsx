import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './NewScan.css';

export default function NewScan() {
  const navigate = useNavigate();
  const [crawlDepth, setCrawlDepth] = useState(3);
  const [reqLimit, setReqLimit] = useState(10000);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Simulate scan creation
    navigate('/scans/demo-new/progress');
  };

  return (
    <div className="new-scan-container">
      <div className="scan-header-card">
        <div className="scan-header-bg-icon">
          <span className="material-symbols-outlined">radar</span>
        </div>
        
        <div className="scan-header-content">
          <div className="scan-op-id">
            <span className="scan-op-badge">Operation</span>
            <span className="scan-op-dot"></span>
            <span className="scan-op-text">SCN-8842-A</span>
          </div>
          <h1 className="page-title">Configure Security Scan</h1>
          <p className="page-subtitle" style={{maxWidth: '600px'}}>
            Define target parameters, scope constraints, and execution profile for the upcoming automated vulnerability assessment.
          </p>
        </div>
        
        <div style={{position: 'relative', zIndex: 10}}>
          <button className="btn-secondary font-caps" style={{padding: '8px 16px', borderRadius: '12px'}}>
            LOAD TEMPLATE
          </button>
        </div>
      </div>

      <form className="scan-form" onSubmit={handleSubmit}>
        
        {/* Target Details Section */}
        <section className="form-section">
          <div className="section-indicator indicator-primary"></div>
          <div className="section-header">
            <div className="section-header-title">
              <span className="material-symbols-outlined text-muted">target</span>
              <h2>Target Details</h2>
            </div>
            <span className="section-badge">Required</span>
          </div>
          
          <div className="section-body">
            <div className="grid-cols-2">
              <div>
                <label className="form-label font-caps">Target URL</label>
                <div className="input-wrapper">
                  <span className="material-symbols-outlined input-icon">language</span>
                  <input 
                    type="url" 
                    className="form-input-lg font-mono" 
                    placeholder="https://" 
                    defaultValue="https://example.com" 
                    required 
                  />
                </div>
                <p className="text-muted" style={{fontSize: '12px'}}>The primary entry point for the scanner.</p>
              </div>
              
              <div>
                <label className="form-label font-caps">Scan Name</label>
                <div className="input-wrapper">
                  <span className="material-symbols-outlined input-icon">badge</span>
                  <input 
                    type="text" 
                    className="form-input-lg" 
                    defaultValue="Production Scan" 
                    required 
                  />
                </div>
                <p className="text-muted" style={{fontSize: '12px'}}>A descriptive identifier for reports.</p>
              </div>
            </div>
          </div>
        </section>

        {/* Scope Definition Section */}
        <section className="form-section">
          <div className="section-indicator indicator-tertiary"></div>
          <div className="section-header">
            <div className="section-header-title">
              <span className="material-symbols-outlined text-muted">my_location</span>
              <h2>Scope Definition</h2>
            </div>
          </div>
          
          <div className="section-body">
            <div className="grid-cols-3">
              <div className="col-span-2" style={{display: 'flex', flexDirection: 'column', gap: '16px'}}>
                
                <div>
                  <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end'}}>
                    <label className="form-label font-caps">Allowed Domains</label>
                    <button type="button" className="btn-link font-caps text-primary">
                      <span className="material-symbols-outlined icon-small">add</span> Add Domain
                    </button>
                  </div>
                  <div className="list-container">
                    <div className="list-item">
                      <span className="font-mono">*.example.com</span>
                      <button type="button" className="delete-btn"><span className="material-symbols-outlined icon-small">close</span></button>
                    </div>
                    <div className="list-item">
                      <span className="font-mono">api.example-internal.net</span>
                      <button type="button" className="delete-btn"><span className="material-symbols-outlined icon-small">close</span></button>
                    </div>
                  </div>
                </div>

                <div>
                  <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end'}}>
                    <label className="form-label font-caps">Excluded Paths (Regex)</label>
                    <button type="button" className="btn-link font-caps text-primary">
                      <span className="material-symbols-outlined icon-small">add</span> Add Path
                    </button>
                  </div>
                  <div className="list-container">
                    <div className="list-item">
                      <span className="font-mono text-muted">^/admin/.*$</span>
                      <button type="button" className="delete-btn"><span className="material-symbols-outlined icon-small">close</span></button>
                    </div>
                    <div className="list-item">
                      <span className="font-mono text-muted">^/logout.*$</span>
                      <button type="button" className="delete-btn"><span className="material-symbols-outlined icon-small">close</span></button>
                    </div>
                  </div>
                </div>

              </div>

              <div className="limits-panel">
                <h3 className="font-caps m-0" style={{marginBottom: '16px'}}>Traversal Limits</h3>
                
                <div style={{marginBottom: '16px'}}>
                  <div style={{display: 'flex', justifyContent: 'space-between', marginBottom: '8px'}}>
                    <label style={{fontSize: '12px'}} className="text-muted">Max Crawl Depth</label>
                    <span className="font-mono-sm" style={{background: 'var(--color-surface-container-highest)', padding: '2px 8px', borderRadius: '6px'}}>{crawlDepth}</span>
                  </div>
                  <input 
                    type="range" 
                    className="range-input" 
                    min="1" max="10" 
                    value={crawlDepth}
                    onChange={(e) => setCrawlDepth(parseInt(e.target.value))}
                  />
                </div>

                <div style={{marginBottom: '16px'}}>
                  <div style={{display: 'flex', justifyContent: 'space-between', marginBottom: '8px'}}>
                    <label style={{fontSize: '12px'}} className="text-muted">Request Limit</label>
                    <span className="font-mono-sm" style={{background: 'var(--color-surface-container-highest)', padding: '2px 8px', borderRadius: '6px'}}>{reqLimit.toLocaleString()}</span>
                  </div>
                  <input 
                    type="range" 
                    className="range-input" 
                    min="1000" max="50000" step="1000"
                    value={reqLimit}
                    onChange={(e) => setReqLimit(parseInt(e.target.value))}
                  />
                </div>

                <div style={{borderTop: '1px solid var(--color-outline-variant)', paddingTop: '16px', display: 'flex', alignItems: 'center', gap: '8px'}}>
                  <input type="checkbox" id="respect-robots" defaultChecked style={{accentColor: 'var(--color-primary-container)'}} />
                  <label htmlFor="respect-robots" style={{fontSize: '12px', cursor: 'pointer'}}>Respect robots.txt</label>
                </div>

              </div>
            </div>
          </div>
        </section>

        <div className="grid-cols-2">
          {/* Discovery Modules */}
          <section className="form-section">
            <div className="section-indicator indicator-secondary"></div>
            <div className="section-header">
              <div className="section-header-title">
                <span className="material-symbols-outlined text-muted">travel_explore</span>
                <h2>Discovery Modules</h2>
              </div>
            </div>
            <div className="section-body" style={{display: 'flex', flexDirection: 'column', gap: '12px'}}>
              
              <label className="module-card">
                <input type="checkbox" defaultChecked style={{marginTop: '4px', accentColor: 'var(--color-primary-container)'}} />
                <div style={{flex: 1}}>
                  <div style={{fontWeight: 600}}>Web Crawling</div>
                  <div style={{fontSize: '12px'}} className="text-muted">Spider HTML, extract links, and build site structure. Includes form detection.</div>
                </div>
                <span className="material-symbols-outlined module-card-icon">download_for_offline</span>
              </label>

              <label className="module-card">
                <input type="checkbox" defaultChecked style={{marginTop: '4px', accentColor: 'var(--color-primary-container)'}} />
                <div style={{flex: 1}}>
                  <div style={{fontWeight: 600}}>JavaScript Analysis</div>
                  <div style={{fontSize: '12px'}} className="text-muted">Execute DOM, find hidden endpoints, and analyze client-side logic in headless browser.</div>
                </div>
                <span className="material-symbols-outlined module-card-icon">javascript</span>
              </label>

              <label className="module-card">
                <input type="checkbox" defaultChecked style={{marginTop: '4px', accentColor: 'var(--color-primary-container)'}} />
                <div style={{flex: 1}}>
                  <div style={{fontWeight: 600}}>API Discovery</div>
                  <div style={{fontSize: '12px'}} className="text-muted">Detect REST/GraphQL endpoints, attempt schema extraction, and guess common paths.</div>
                </div>
                <span className="material-symbols-outlined module-card-icon">api</span>
              </label>

              <label className="module-card">
                <input type="checkbox" style={{marginTop: '4px', accentColor: 'var(--color-primary-container)'}} />
                <div style={{flex: 1}}>
                  <div style={{fontWeight: 600}}>Subdomain Enumeration</div>
                  <div style={{fontSize: '12px'}} className="text-muted">Passive DNS analysis and active brute-forcing for related infrastructure.</div>
                </div>
                <span className="material-symbols-outlined module-card-icon">dns</span>
              </label>

            </div>
          </section>

          {/* Testing Profile */}
          <section className="form-section">
            <div className="section-indicator indicator-error"></div>
            <div className="section-header">
              <div className="section-header-title">
                <span className="material-symbols-outlined text-muted">speed</span>
                <h2>Testing Profile</h2>
              </div>
            </div>
            <div className="section-body" style={{display: 'flex', flexDirection: 'column', gap: '12px'}}>
              
              <label className="profile-card">
                <input type="radio" name="profile" style={{marginTop: '4px', accentColor: 'var(--color-primary-container)'}} />
                <div style={{flex: 1}}>
                  <div className="profile-title">Passive</div>
                  <div style={{fontSize: '12px'}} className="text-muted">Safe. Observes traffic without injecting payloads.</div>
                  <div style={{marginTop: '8px'}}><span className="section-badge">Speed: Slow</span></div>
                </div>
              </label>

              <label className="profile-card selected">
                <input type="radio" name="profile" defaultChecked style={{marginTop: '4px', accentColor: 'var(--color-primary-container)'}} />
                <div style={{flex: 1}}>
                  <div className="profile-title">Standard</div>
                  <div style={{fontSize: '12px'}} className="text-muted">Balanced. Injects common payloads, respects rate limits.</div>
                  <div style={{marginTop: '8px', display: 'flex', gap: '8px'}}>
                    <span className="section-badge" style={{background: 'rgba(88,166,255,0.2)', color: 'var(--color-primary-container)'}}>Recommended</span>
                    <span className="section-badge">Speed: Normal</span>
                  </div>
                </div>
              </label>

              <label className="profile-card">
                <input type="radio" name="profile" style={{marginTop: '4px', accentColor: 'var(--color-error)'}} />
                <div style={{flex: 1}}>
                  <div className="profile-title">Aggressive</div>
                  <div style={{fontSize: '12px'}} className="text-muted">Loud. High concurrency, exhaustive fuzzing, ignores limits.</div>
                  <div style={{marginTop: '8px'}}>
                    <span className="section-badge" style={{background: 'rgba(255,180,171,0.2)', color: 'var(--color-error)'}}>Warning: High Load</span>
                  </div>
                </div>
              </label>

            </div>
          </section>
        </div>

        <div className="scan-footer">
          <button type="button" className="btn-link font-caps text-muted" onClick={() => navigate(-1)}>CANCEL</button>
          
          <div style={{display: 'flex', alignItems: 'center', gap: '16px'}}>
            <span className="font-mono-sm text-muted" style={{display: 'flex', alignItems: 'center', gap: '8px'}}>
              <span className="scan-op-dot bg-tertiary pulse"></span>
              Est. Duration: 2-4 hours
            </span>
            <button type="submit" className="btn-start-scan">
              <span className="material-symbols-outlined">play_arrow</span>
              START SCAN
            </button>
          </div>
        </div>

      </form>
    </div>
  );
}
