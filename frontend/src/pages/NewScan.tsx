import React, { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { scanService } from '../services/api';
import './NewScan.css';

export default function NewScan() {
  const navigate = useNavigate();
  
  // 1. Target Details
  const [targetUrl, setTargetUrl] = useState("https://example.com");
  const [scanName, setScanName] = useState("Production Scan");
  
  // 2. Scope Definition
  const [allowedDomains, setAllowedDomains] = useState<string[]>(["*.example.com", "api.example-internal.net"]);
  const [newDomainInput, setNewDomainInput] = useState("");
  const [showDomainInput, setShowDomainInput] = useState(false);

  const [excludedPaths, setExcludedPaths] = useState<string[]>(["^/admin/.*$", "^/logout.*$"]);
  const [newPathInput, setNewPathInput] = useState("");
  const [showPathInput, setShowPathInput] = useState(false);

  // 3. Traversal Limits
  const [crawlDepth, setCrawlDepth] = useState(3);
  const [reqLimit, setReqLimit] = useState(10000);
  const [respectRobots, setRespectRobots] = useState(true);

  // 4. Discovery Modules
  const [enableWebCrawling, setEnableWebCrawling] = useState(true);
  const [enableJsAnalysis, setEnableJsAnalysis] = useState(true);
  const [enableApiDiscovery, setEnableApiDiscovery] = useState(true);
  const [enableSubdomainDiscovery, setEnableSubdomainDiscovery] = useState(false);

  // 5. Testing Profile
  const [scanMode, setScanMode] = useState<"Passive" | "Standard" | "Aggressive">("Standard");
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Dynamic Estimation calculation
  const estimatedDuration = useMemo(() => {
    let baseMinutes = 15;
    
    // Impact of depth
    baseMinutes += crawlDepth * 12;
    
    // Impact of request limits
    baseMinutes += Math.round((reqLimit / 1000) * 4);
    
    // Impact of discovery modules
    if (enableJsAnalysis) baseMinutes += 20;
    if (enableApiDiscovery) baseMinutes += 15;
    if (enableSubdomainDiscovery) baseMinutes += 25;
    
    // Impact of Profile
    if (scanMode === "Passive") baseMinutes = Math.round(baseMinutes * 0.5);
    if (scanMode === "Aggressive") baseMinutes = Math.round(baseMinutes * 1.8);

    const hours = (baseMinutes / 60).toFixed(1);
    if (baseMinutes < 60) {
      return `Est. Duration: ~${baseMinutes} mins`;
    }
    return `Est. Duration: ~${hours} hours`;
  }, [crawlDepth, reqLimit, enableJsAnalysis, enableApiDiscovery, enableSubdomainDiscovery, scanMode]);

  // Handle Domain additions/deletions
  const handleAddDomain = () => {
    if (newDomainInput.trim()) {
      setAllowedDomains([...allowedDomains, newDomainInput.trim()]);
      setNewDomainInput("");
      setShowDomainInput(false);
    }
  };

  const handleRemoveDomain = (idx: number) => {
    setAllowedDomains(allowedDomains.filter((_, i) => i !== idx));
  };

  // Handle Path additions/deletions
  const handleAddPath = () => {
    if (newPathInput.trim()) {
      setExcludedPaths([...excludedPaths, newPathInput.trim()]);
      setNewPathInput("");
      setShowPathInput(false);
    }
  };

  const handleRemovePath = (idx: number) => {
    setExcludedPaths(excludedPaths.filter((_, i) => i !== idx));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      const data = await scanService.createScan({
        target_url: targetUrl,
        scan_mode: scanMode,
        max_depth: crawlDepth,
        max_requests: reqLimit,
        enable_subdomain_discovery: enableSubdomainDiscovery,
        enable_directory_discovery: enableApiDiscovery
      });
      localStorage.setItem('last_active_scan_id', data.scan_id);
      navigate(`/scans/${data.scan_id}/progress`);
    } catch (error: any) {
      console.error(error);
      alert(`Failed to start scan: ${error.message || error}`);
      setIsSubmitting(false);
    }
  };

  return (
    <div className="new-scan-container">
      {/* Header with Back Button */}
      <div className="scan-header-card">
        <div className="scan-header-bg-icon">
          <span className="material-symbols-outlined">radar</span>
        </div>
        
        <div className="scan-header-content">
          <div style={{display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px'}}>
            <button type="button" className="btn-back" onClick={() => navigate(-1)} title="Back to Dashboard">
              <span className="material-symbols-outlined">arrow_back</span>
            </button>
            <div className="scan-op-id">
              <span className="scan-op-badge">Operation</span>
              <span className="scan-op-dot"></span>
              <span className="scan-op-text">CYPHER-CONFIG</span>
            </div>
          </div>
          <h1 className="page-title">Configure Security Scan</h1>
          <p className="page-subtitle" style={{maxWidth: '640px'}}>
            Define target parameters, scope constraints, and execution profile for the upcoming automated vulnerability assessment.
          </p>
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
                <label className="form-label font-caps">TARGET URL</label>
                <div className="input-wrapper">
                  <span className="material-symbols-outlined input-icon">language</span>
                  <input 
                    type="url" 
                    className="form-input-lg font-mono" 
                    placeholder="https://example.com" 
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    required 
                  />
                </div>
                <p className="text-muted" style={{fontSize: '12px', marginTop: '6px'}}>The primary entry point for the scanner.</p>
              </div>
              
              <div>
                <label className="form-label font-caps">SCAN NAME</label>
                <div className="input-wrapper">
                  <span className="material-symbols-outlined input-icon">badge</span>
                  <input 
                    type="text" 
                    className="form-input-lg" 
                    value={scanName}
                    onChange={(e) => setScanName(e.target.value)}
                    required 
                  />
                </div>
                <p className="text-muted" style={{fontSize: '12px', marginTop: '6px'}}>A descriptive identifier for reports.</p>
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
                
                {/* Allowed Domains */}
                <div>
                  <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '6px'}}>
                    <label className="form-label font-caps">ALLOWED DOMAINS</label>
                    <button 
                      type="button" 
                      className="btn-link font-caps text-primary"
                      onClick={() => setShowDomainInput(true)}
                    >
                      <span className="material-symbols-outlined icon-small">add</span> Add Domain
                    </button>
                  </div>
                  
                  {showDomainInput && (
                    <div style={{display: 'flex', gap: '8px', marginBottom: '8px'}}>
                      <input 
                        type="text" 
                        className="form-input" 
                        placeholder="*.subdomain.com"
                        value={newDomainInput}
                        onChange={(e) => setNewDomainInput(e.target.value)}
                      />
                      <button type="button" className="btn-primary-small" onClick={handleAddDomain}>Add</button>
                      <button type="button" className="btn-outline-small" onClick={() => setShowDomainInput(false)}>Cancel</button>
                    </div>
                  )}

                  <div className="list-container">
                    {allowedDomains.map((dom, idx) => (
                      <div key={idx} className="list-item">
                        <span className="font-mono">{dom}</span>
                        <button type="button" className="delete-btn" onClick={() => handleRemoveDomain(idx)}>
                          <span className="material-symbols-outlined icon-small">close</span>
                        </button>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Excluded Paths */}
                <div>
                  <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '6px'}}>
                    <label className="form-label font-caps">EXCLUDED PATHS (REGEX)</label>
                    <button 
                      type="button" 
                      className="btn-link font-caps text-primary"
                      onClick={() => setShowPathInput(true)}
                    >
                      <span className="material-symbols-outlined icon-small">add</span> Add Path
                    </button>
                  </div>

                  {showPathInput && (
                    <div style={{display: 'flex', gap: '8px', marginBottom: '8px'}}>
                      <input 
                        type="text" 
                        className="form-input" 
                        placeholder="^/sensitive/.*$"
                        value={newPathInput}
                        onChange={(e) => setNewPathInput(e.target.value)}
                      />
                      <button type="button" className="btn-primary-small" onClick={handleAddPath}>Add</button>
                      <button type="button" className="btn-outline-small" onClick={() => setShowPathInput(false)}>Cancel</button>
                    </div>
                  )}

                  <div className="list-container">
                    {excludedPaths.map((path, idx) => (
                      <div key={idx} className="list-item">
                        <span className="font-mono text-muted">{path}</span>
                        <button type="button" className="delete-btn" onClick={() => handleRemovePath(idx)}>
                          <span className="material-symbols-outlined icon-small">close</span>
                        </button>
                      </div>
                    ))}
                  </div>
                </div>

              </div>

              {/* Traversal Limits */}
              <div className="limits-panel">
                <h3 className="font-caps m-0" style={{marginBottom: '16px', fontSize: '13px'}}>TRAVERSAL LIMITS</h3>
                
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
                  <input 
                    type="checkbox" 
                    id="respect-robots" 
                    checked={respectRobots}
                    onChange={(e) => setRespectRobots(e.target.checked)}
                    style={{accentColor: 'var(--color-primary-container)'}} 
                  />
                  <label htmlFor="respect-robots" style={{fontSize: '12px', cursor: 'pointer'}}>Respect robots.txt</label>
                </div>

              </div>
            </div>
          </div>
        </section>

        {/* Discovery Modules & Testing Profile */}
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
                <input 
                  type="checkbox" 
                  checked={enableWebCrawling} 
                  onChange={(e) => setEnableWebCrawling(e.target.checked)}
                  style={{marginTop: '4px', accentColor: 'var(--color-primary-container)'}} 
                />
                <div style={{flex: 1}}>
                  <div style={{fontWeight: 600}}>Web Crawling</div>
                  <div style={{fontSize: '12px'}} className="text-muted">Spider HTML, extract links, and build site structure. Includes form detection.</div>
                </div>
                <span className="material-symbols-outlined module-card-icon">download_for_offline</span>
              </label>

              <label className="module-card">
                <input 
                  type="checkbox" 
                  checked={enableJsAnalysis}
                  onChange={(e) => setEnableJsAnalysis(e.target.checked)}
                  style={{marginTop: '4px', accentColor: 'var(--color-primary-container)'}} 
                />
                <div style={{flex: 1}}>
                  <div style={{fontWeight: 600}}>JavaScript Analysis</div>
                  <div style={{fontSize: '12px'}} className="text-muted">Execute DOM, find hidden endpoints, and analyze client-side logic in headless browser.</div>
                </div>
                <span className="material-symbols-outlined module-card-icon">javascript</span>
              </label>

              <label className="module-card">
                <input 
                  type="checkbox" 
                  checked={enableApiDiscovery}
                  onChange={(e) => setEnableApiDiscovery(e.target.checked)}
                  style={{marginTop: '4px', accentColor: 'var(--color-primary-container)'}} 
                />
                <div style={{flex: 1}}>
                  <div style={{fontWeight: 600}}>API Discovery</div>
                  <div style={{fontSize: '12px'}} className="text-muted">Detect REST/GraphQL endpoints, attempt schema extraction, and guess common paths.</div>
                </div>
                <span className="material-symbols-outlined module-card-icon">api</span>
              </label>

              <label className="module-card">
                <input 
                  type="checkbox" 
                  checked={enableSubdomainDiscovery}
                  onChange={(e) => setEnableSubdomainDiscovery(e.target.checked)}
                  style={{marginTop: '4px', accentColor: 'var(--color-primary-container)'}} 
                />
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
              
              <label className={`profile-card ${scanMode === 'Passive' ? 'selected' : ''}`}>
                <input 
                  type="radio" 
                  name="profile" 
                  checked={scanMode === 'Passive'} 
                  onChange={() => setScanMode('Passive')} 
                  style={{marginTop: '4px', accentColor: 'var(--color-primary-container)'}} 
                />
                <div style={{flex: 1}}>
                  <div className="profile-title">Passive</div>
                  <div style={{fontSize: '12px'}} className="text-muted">Safe. Observes traffic without injecting payloads.</div>
                  <div style={{marginTop: '8px'}}><span className="section-badge">SPEED: SLOW</span></div>
                </div>
              </label>

              <label className={`profile-card ${scanMode === 'Standard' ? 'selected' : ''}`}>
                <input 
                  type="radio" 
                  name="profile" 
                  checked={scanMode === 'Standard'} 
                  onChange={() => setScanMode('Standard')} 
                  style={{marginTop: '4px', accentColor: 'var(--color-primary-container)'}} 
                />
                <div style={{flex: 1}}>
                  <div className="profile-title">Standard</div>
                  <div style={{fontSize: '12px'}} className="text-muted">Balanced. Injects common payloads, respects rate limits.</div>
                  <div style={{marginTop: '8px', display: 'flex', gap: '8px'}}>
                    <span className="section-badge" style={{background: 'rgba(88,166,255,0.2)', color: 'var(--color-primary-container)'}}>RECOMMENDED</span>
                    <span className="section-badge">SPEED: NORMAL</span>
                  </div>
                </div>
              </label>

              <label className={`profile-card ${scanMode === 'Aggressive' ? 'selected' : ''}`}>
                <input 
                  type="radio" 
                  name="profile" 
                  checked={scanMode === 'Aggressive'} 
                  onChange={() => setScanMode('Aggressive')} 
                  style={{marginTop: '4px', accentColor: 'var(--color-error)'}} 
                />
                <div style={{flex: 1}}>
                  <div className="profile-title">Aggressive</div>
                  <div style={{fontSize: '12px'}} className="text-muted">Loud. High concurrency, exhaustive fuzzing, ignores limits.</div>
                  <div style={{marginTop: '8px'}}>
                    <span className="section-badge" style={{background: 'rgba(255,180,171,0.2)', color: 'var(--color-error)'}}>WARNING: HIGH LOAD</span>
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
              {estimatedDuration}
            </span>
            <button type="submit" className="btn-start-scan" disabled={isSubmitting}>
              <span className="material-symbols-outlined">play_arrow</span>
              {isSubmitting ? 'STARTING...' : 'START SCAN'}
            </button>
          </div>
        </div>

      </form>
    </div>
  );
}
