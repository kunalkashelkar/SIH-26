import React, { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { scanService, RepositoryMetadataResponse } from '../services/api';
import './NewScan.css';

export default function NewScan() {
  const navigate = useNavigate();
  
  // 1. Discovery Architecture Mode
  const [discoveryMode, setDiscoveryMode] = useState<"WEBSITE_ONLY" | "GITHUB_ONLY" | "HYBRID">("WEBSITE_ONLY");
  const [repositoryUrl, setRepositoryUrl] = useState("https://github.com/OWASP/NodeGoat");
  const [repositoryBranch, setRepositoryBranch] = useState("main");
  const [repositoryCommitSha, setRepositoryCommitSha] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [repoMetadata, setRepoMetadata] = useState<RepositoryMetadataResponse | null>(null);
  const [isValidatingRepo, setIsValidatingRepo] = useState(false);
  const [repoValidationStatus, setRepoValidationStatus] = useState<{
    status: 'idle' | 'validating' | 'valid' | 'invalid';
    message: string;
  }>({ status: 'idle', message: '' });

  // 2. Target Details
  const [targetUrl, setTargetUrl] = useState("https://example.com");
  const [scanName, setScanName] = useState("Production Scan");
  
  // Optional Authentication Details
  const [showAuthSettings, setShowAuthSettings] = useState(false);
  const [sessionCookie, setSessionCookie] = useState("");
  const [authHeader, setAuthHeader] = useState("");

  // Validation feedback
  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});

  const handleValidateRepository = async () => {
    if (!repositoryUrl.trim()) {
      setRepoValidationStatus({ status: 'invalid', message: 'GitHub repository URL is required.' });
      return;
    }
    setIsValidatingRepo(true);
    setRepoValidationStatus({ status: 'validating', message: 'Connecting to GitHub API...' });
    try {
      const meta = await scanService.validateRepository({
        repository_url: repositoryUrl.trim(),
        branch: repositoryBranch.trim() || undefined,
        commit_sha: repositoryCommitSha.trim() || undefined,
        github_token: githubToken.trim() || undefined
      });
      setRepoMetadata(meta);
      if (meta.valid) {
        if (meta.selected_branch) setRepositoryBranch(meta.selected_branch);
        if (meta.resolved_commit_sha) setRepositoryCommitSha(meta.resolved_commit_sha);
        setRepoValidationStatus({
          status: 'valid',
          message: meta.message || `Connected to ${meta.owner}/${meta.repository} (${meta.visibility})`
        });
      } else {
        setRepoValidationStatus({
          status: 'invalid',
          message: meta.message || 'Unable to access repository.'
        });
      }
    } catch (err: any) {
      setRepoValidationStatus({
        status: 'invalid',
        message: err.message || 'Validation request failed.'
      });
    } finally {
      setIsValidatingRepo(false);
    }
  };
  
  // 3. Scope Definition
  const [allowedDomains, setAllowedDomains] = useState<string[]>(["*.example.com", "api.example-internal.net"]);
  const [newDomainInput, setNewDomainInput] = useState("");
  const [showDomainInput, setShowDomainInput] = useState(false);

  const [excludedPaths, setExcludedPaths] = useState<string[]>(["^/admin/.*$", "^/logout.*$"]);
  const [newPathInput, setNewPathInput] = useState("");
  const [showPathInput, setShowPathInput] = useState(false);

  // 4. Traversal Limits
  const [crawlDepth, setCrawlDepth] = useState(3);
  const [reqLimit, setReqLimit] = useState(10000);
  const [respectRobots, setRespectRobots] = useState(true);

  // 5. Discovery Modules
  const [enableWebCrawling, setEnableWebCrawling] = useState(true);
  const [enableJsAnalysis, setEnableJsAnalysis] = useState(true);
  const [enableApiDiscovery, setEnableApiDiscovery] = useState(true);
  const [enableSubdomainDiscovery, setEnableSubdomainDiscovery] = useState(false);

  // 6. Testing Profile
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
    if (discoveryMode === "HYBRID") baseMinutes += 15;
    
    // Impact of Profile
    if (scanMode === "Passive") baseMinutes = Math.round(baseMinutes * 0.5);
    if (scanMode === "Aggressive") baseMinutes = Math.round(baseMinutes * 1.8);

    const hours = (baseMinutes / 60).toFixed(1);
    if (baseMinutes < 60) {
      return `Est. Duration: ~${baseMinutes} mins`;
    }
    return `Est. Duration: ~${hours} hours`;
  }, [crawlDepth, reqLimit, enableJsAnalysis, enableApiDiscovery, enableSubdomainDiscovery, scanMode, discoveryMode]);

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
    setValidationErrors({});

    // Validate inputs
    const errors: Record<string, string> = {};
    if (discoveryMode === "WEBSITE_ONLY" || discoveryMode === "HYBRID") {
      if (!targetUrl.trim()) {
        errors.targetUrl = "Authorized website URL is required.";
      } else if (!/^https?:\/\/.+/i.test(targetUrl.trim())) {
        errors.targetUrl = "Must be a valid HTTP or HTTPS URL (e.g. https://example.com).";
      }
    }
    if (discoveryMode === "GITHUB_ONLY" || discoveryMode === "HYBRID") {
      if (!repositoryUrl.trim()) {
        errors.repositoryUrl = "GitHub repository URL is required.";
      } else if (!repositoryUrl.trim().includes("github.com") && !repositoryUrl.trim().startsWith("git@")) {
        errors.repositoryUrl = "Must be a valid GitHub URL (e.g. https://github.com/owner/repo).";
      }
    }

    if (Object.keys(errors).length > 0) {
      setValidationErrors(errors);
      return;
    }

    setIsSubmitting(true);
    try {
      const payload: any = {
        discovery_mode: discoveryMode,
        scan_mode: scanMode,
        max_depth: crawlDepth,
        max_requests: reqLimit,
        enable_subdomain_discovery: enableSubdomainDiscovery,
        enable_directory_discovery: enableApiDiscovery,
        allowed_domains: allowedDomains,
        excluded_paths: excludedPaths
      };

      if (discoveryMode === "WEBSITE_ONLY" || discoveryMode === "HYBRID") {
        payload.website_url = targetUrl.trim();
        payload.target_url = targetUrl.trim();
        if (sessionCookie.trim()) payload.session_cookie = sessionCookie.trim();
        if (authHeader.trim()) payload.auth_header = authHeader.trim();
      }
      if (discoveryMode === "GITHUB_ONLY" || discoveryMode === "HYBRID") {
        payload.repository_url = repositoryUrl.trim();
        payload.repository_branch = repositoryBranch.trim() || "main";
        if (repositoryCommitSha.trim()) payload.repository_commit_sha = repositoryCommitSha.trim();
        if (githubToken.trim()) payload.github_token = githubToken.trim();
      }

      const data = await scanService.createScan(payload);
      localStorage.setItem('last_active_scan_id', data.scan_id);
      navigate(`/scans/${data.scan_id}/progress`);
    } catch (error: any) {
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
        
        {/* Discovery Architecture Mode Selector */}
        <section className="form-section">
          <div className="section-indicator indicator-primary"></div>
          <div className="section-header">
            <div className="section-header-title">
              <span className="material-symbols-outlined text-muted">hub</span>
              <h2>Discovery Architecture Mode</h2>
            </div>
            <span className="section-badge font-mono">PHASE 1 FOUNDATION</span>
          </div>
          
          <div className="section-body">
            <div style={{display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px'}}>
              <div 
                className={`profile-card ${discoveryMode === 'WEBSITE_ONLY' ? 'selected' : ''}`}
                onClick={() => setDiscoveryMode('WEBSITE_ONLY')}
                style={{cursor: 'pointer', padding: '16px', borderRadius: '8px', border: discoveryMode === 'WEBSITE_ONLY' ? '2px solid #00f0ff' : '1px solid rgba(255,255,255,0.1)', background: discoveryMode === 'WEBSITE_ONLY' ? 'rgba(0, 240, 255, 0.08)' : 'rgba(255,255,255,0.02)'}}
              >
                <div style={{display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px'}}>
                  <span className="material-symbols-outlined" style={{color: '#00f0ff'}}>language</span>
                  <h3 style={{fontSize: '15px', fontWeight: 600, margin: 0}}>Website Only</h3>
                </div>
                <p style={{fontSize: '12px', color: '#94a3b8', margin: 0}}>Static and dynamic crawl, JavaScript rendering, forms, and observed APIs.</p>
              </div>

              <div 
                className={`profile-card ${discoveryMode === 'GITHUB_ONLY' ? 'selected' : ''}`}
                onClick={() => setDiscoveryMode('GITHUB_ONLY')}
                style={{cursor: 'pointer', padding: '16px', borderRadius: '8px', border: discoveryMode === 'GITHUB_ONLY' ? '2px solid #a855f7' : '1px solid rgba(255,255,255,0.1)', background: discoveryMode === 'GITHUB_ONLY' ? 'rgba(168, 85, 247, 0.08)' : 'rgba(255,255,255,0.02)'}}
              >
                <div style={{display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px'}}>
                  <span className="material-symbols-outlined" style={{color: '#a855f7'}}>code</span>
                  <h3 style={{fontSize: '15px', fontWeight: 600, margin: 0}}>GitHub Repo Only</h3>
                </div>
                <p style={{fontSize: '12px', color: '#94a3b8', margin: 0}}>Source code AST analysis, backend routers, controllers, and schemas.</p>
              </div>

              <div 
                className={`profile-card ${discoveryMode === 'HYBRID' ? 'selected' : ''}`}
                onClick={() => setDiscoveryMode('HYBRID')}
                style={{cursor: 'pointer', padding: '16px', borderRadius: '8px', border: discoveryMode === 'HYBRID' ? '2px solid #10b981' : '1px solid rgba(255,255,255,0.1)', background: discoveryMode === 'HYBRID' ? 'rgba(16, 185, 129, 0.08)' : 'rgba(255,255,255,0.02)'}}
              >
                <div style={{display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px'}}>
                  <span className="material-symbols-outlined" style={{color: '#10b981'}}>alt_route</span>
                  <h3 style={{fontSize: '15px', fontWeight: 600, margin: 0}}>Combined Hybrid</h3>
                </div>
                <p style={{fontSize: '12px', color: '#94a3b8', margin: 0}}>Cross-correlates source code routes with live runtime website endpoints.</p>
              </div>
            </div>
          </div>
        </section>

        {/* Target Details Section */}
        <section className="form-section">
          <div className="section-indicator indicator-primary"></div>
          <div className="section-header">
            <div className="section-header-title">
              <span className="material-symbols-outlined text-muted">target</span>
              <h2>Scope & Target Parameters</h2>
            </div>
            <span className="section-badge">Required</span>
          </div>
          
          <div className="section-body">
            <div className="grid-cols-2">
              {(discoveryMode === "WEBSITE_ONLY" || discoveryMode === "HYBRID") && (
                <div>
                  <label className="form-label font-caps">AUTHORIZED WEBSITE URL</label>
                  <div className="input-wrapper">
                    <span className="material-symbols-outlined input-icon">language</span>
                    <input 
                      type="url" 
                      className={`form-input-lg font-mono ${validationErrors.targetUrl ? 'border-error' : ''}`}
                      placeholder="https://example.com" 
                      value={targetUrl}
                      onChange={(e) => {
                        setTargetUrl(e.target.value);
                        if (validationErrors.targetUrl) setValidationErrors({...validationErrors, targetUrl: ""});
                      }}
                      required 
                    />
                  </div>
                  {validationErrors.targetUrl ? (
                    <p style={{fontSize: '12px', color: 'var(--color-error)', marginTop: '4px'}}>{validationErrors.targetUrl}</p>
                  ) : (
                    <p className="text-muted" style={{fontSize: '12px', marginTop: '6px'}}>Live web application endpoint for crawling & fuzzing.</p>
                  )}
                </div>
              )}

              {(discoveryMode === "GITHUB_ONLY" || discoveryMode === "HYBRID") && (
                <div style={{display: 'flex', flexDirection: 'column', gap: '14px'}}>
                  <div>
                    <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px'}}>
                      <label className="form-label font-caps" style={{margin: 0}}>GITHUB REPOSITORY URL</label>
                      <button
                        type="button"
                        onClick={handleValidateRepository}
                        disabled={isValidatingRepo || !repositoryUrl.trim()}
                        style={{
                          background: 'rgba(168, 85, 247, 0.15)',
                          border: '1px solid rgba(168, 85, 247, 0.4)',
                          color: '#c084fc',
                          padding: '3px 10px',
                          borderRadius: '4px',
                          fontSize: '11px',
                          fontWeight: 600,
                          cursor: isValidatingRepo ? 'not-allowed' : 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '6px'
                        }}
                      >
                        <span className={`material-symbols-outlined ${isValidatingRepo ? 'spin-icon' : ''}`} style={{fontSize: '14px'}}>
                          {isValidatingRepo ? 'sync' : 'verified'}
                        </span>
                        {isValidatingRepo ? 'Validating...' : 'Validate Repository'}
                      </button>
                    </div>
                    <div className="input-wrapper">
                      <span className="material-symbols-outlined input-icon">code</span>
                      <input 
                        type="url" 
                        className={`form-input-lg font-mono ${validationErrors.repositoryUrl ? 'border-error' : ''}`}
                        placeholder="https://github.com/owner/repository" 
                        value={repositoryUrl}
                        onChange={(e) => {
                          setRepositoryUrl(e.target.value);
                          if (validationErrors.repositoryUrl) setValidationErrors({...validationErrors, repositoryUrl: ""});
                          if (repoValidationStatus.status !== 'idle') {
                            setRepoValidationStatus({ status: 'idle', message: '' });
                          }
                        }}
                        required 
                      />
                    </div>
                    {validationErrors.repositoryUrl && (
                      <p style={{fontSize: '12px', color: 'var(--color-error)', marginTop: '4px'}}>{validationErrors.repositoryUrl}</p>
                    )}
                    {repoValidationStatus.message && (
                      <div style={{
                        marginTop: '8px',
                        padding: '8px 12px',
                        borderRadius: '6px',
                        fontSize: '12px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                        background: repoValidationStatus.status === 'valid' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                        border: `1px solid ${repoValidationStatus.status === 'valid' ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
                        color: repoValidationStatus.status === 'valid' ? '#10b981' : '#ef4444'
                      }}>
                        <span className="material-symbols-outlined" style={{fontSize: '16px'}}>
                          {repoValidationStatus.status === 'valid' ? 'check_circle' : 'error'}
                        </span>
                        <span>{repoValidationStatus.message}</span>
                      </div>
                    )}
                  </div>

                  {/* Repository Metadata Card (when validated) */}
                  {repoMetadata && repoMetadata.valid && (
                    <div style={{
                      background: 'rgba(255, 255, 255, 0.03)',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      borderRadius: '8px',
                      padding: '12px 16px',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '8px'
                    }}>
                      <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                        <div style={{display: 'flex', alignItems: 'center', gap: '8px'}}>
                          <span className="material-symbols-outlined" style={{color: '#a855f7', fontSize: '18px'}}>folder_code</span>
                          <span style={{fontWeight: 600, fontSize: '13px', color: '#fff'}}>
                            {repoMetadata.owner} / {repoMetadata.repository}
                          </span>
                        </div>
                        <span style={{
                          fontSize: '10px',
                          fontWeight: 700,
                          padding: '2px 8px',
                          borderRadius: '12px',
                          textTransform: 'uppercase',
                          background: repoMetadata.visibility === 'public' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                          color: repoMetadata.visibility === 'public' ? '#10b981' : '#f59e0b',
                          border: `1px solid ${repoMetadata.visibility === 'public' ? 'rgba(16, 185, 129, 0.3)' : 'rgba(245, 158, 11, 0.3)'}`
                        }}>
                          {repoMetadata.visibility}
                        </span>
                      </div>

                      <div style={{display: 'flex', flexWrap: 'wrap', gap: '14px', fontSize: '12px', color: '#94a3b8'}}>
                        {repoMetadata.primary_language && (
                          <span style={{display: 'flex', alignItems: 'center', gap: '4px'}}>
                            <span className="material-symbols-outlined" style={{fontSize: '14px', color: '#38bdf8'}}>code</span>
                            {repoMetadata.primary_language}
                          </span>
                        )}
                        {repoMetadata.stars_count !== undefined && repoMetadata.stars_count !== null && (
                          <span style={{display: 'flex', alignItems: 'center', gap: '4px'}}>
                            <span className="material-symbols-outlined" style={{fontSize: '14px', color: '#facc15'}}>star</span>
                            {repoMetadata.stars_count}
                          </span>
                        )}
                        {repoMetadata.resolved_commit_sha && (
                          <span style={{display: 'flex', alignItems: 'center', gap: '4px', fontFamily: 'monospace'}}>
                            <span className="material-symbols-outlined" style={{fontSize: '14px'}}>commit</span>
                            {repoMetadata.resolved_commit_sha.slice(0, 8)}
                          </span>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Branch & Commit Selection */}
                  <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px'}}>
                    <div>
                      <label className="form-label font-caps">BRANCH</label>
                      <div className="input-wrapper">
                        <span className="material-symbols-outlined input-icon">fork_right</span>
                        {repoMetadata?.available_branches && repoMetadata.available_branches.length > 0 ? (
                          <select
                            className="form-input-lg font-mono"
                            value={repositoryBranch}
                            onChange={(e) => setRepositoryBranch(e.target.value)}
                            style={{background: 'var(--color-surface, #111)', color: '#fff'}}
                          >
                            {repoMetadata.available_branches.map((b) => (
                              <option key={b} value={b}>{b}</option>
                            ))}
                          </select>
                        ) : (
                          <input 
                            type="text" 
                            className="form-input-lg font-mono" 
                            value={repositoryBranch}
                            onChange={(e) => setRepositoryBranch(e.target.value)}
                            placeholder="main" 
                          />
                        )}
                      </div>
                    </div>
                    <div>
                      <label className="form-label font-caps">COMMIT SHA (OPTIONAL)</label>
                      <div className="input-wrapper">
                        <span className="material-symbols-outlined input-icon">commit</span>
                        <input 
                          type="text" 
                          className="form-input-lg font-mono" 
                          value={repositoryCommitSha}
                          onChange={(e) => setRepositoryCommitSha(e.target.value)}
                          placeholder="e.g. 7b3e1a0" 
                        />
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </section>

        {/* Authentication & Session Configuration (Optional) */}
        <section className="form-section">
          <div className="section-indicator indicator-secondary"></div>
          <div className="section-header" style={{cursor: 'pointer'}} onClick={() => setShowAuthSettings(!showAuthSettings)}>
            <div className="section-header-title">
              <span className="material-symbols-outlined text-muted">lock</span>
              <h2>Authentication Context & Authorization</h2>
            </div>
            <button type="button" className="btn-link font-caps text-primary" style={{cursor: 'pointer'}}>
              {showAuthSettings ? 'Hide' : 'Configure (Optional)'}
            </button>
          </div>
          
          {showAuthSettings && (
            <div className="section-body">
              <div className="grid-cols-2">
                {(discoveryMode === "WEBSITE_ONLY" || discoveryMode === "HYBRID") && (
                  <div>
                    <label className="form-label font-caps">SESSION COOKIE</label>
                    <div className="input-wrapper">
                      <span className="material-symbols-outlined input-icon">cookie</span>
                      <input 
                        type="password" 
                        className="form-input-lg font-mono" 
                        placeholder="session_id=...; token=..." 
                        value={sessionCookie}
                        onChange={(e) => setSessionCookie(e.target.value)}
                      />
                    </div>
                    <p className="text-muted" style={{fontSize: '12px', marginTop: '6px'}}>Optional authenticated session cookie for authorized crawling.</p>
                  </div>
                )}

                {(discoveryMode === "WEBSITE_ONLY" || discoveryMode === "HYBRID") && (
                  <div>
                    <label className="form-label font-caps">AUTHORIZATION HEADER</label>
                    <div className="input-wrapper">
                      <span className="material-symbols-outlined input-icon">key</span>
                      <input 
                        type="password" 
                        className="form-input-lg font-mono" 
                        placeholder="Bearer eyJhbGci..." 
                        value={authHeader}
                        onChange={(e) => setAuthHeader(e.target.value)}
                      />
                    </div>
                    <p className="text-muted" style={{fontSize: '12px', marginTop: '6px'}}>Authorization header string injected into HTTP crawl requests.</p>
                  </div>
                )}

                {(discoveryMode === "GITHUB_ONLY" || discoveryMode === "HYBRID") && (
                  <div>
                    <label className="form-label font-caps">GITHUB ACCESS TOKEN (PRIVATE REPOS)</label>
                    <div className="input-wrapper">
                      <span className="material-symbols-outlined input-icon">token</span>
                      <input 
                        type="password" 
                        className="form-input-lg font-mono" 
                        placeholder="ghp_xxxxxxxxxxxxxxxxxxxx" 
                        value={githubToken}
                        onChange={(e) => setGithubToken(e.target.value)}
                      />
                    </div>
                    <p className="text-muted" style={{fontSize: '12px', marginTop: '6px'}}>Personal access token with read permissions for private repository acquisition.</p>
                  </div>
                )}
              </div>
            </div>
          )}
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
