import React, { useState, useEffect, useMemo, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  scanService,
  UnifiedInventoryResponse,
  DiscoveredAssetItem,
  ScanStatusResponse,
  GraphResponse,
  GraphNode
} from '../services/api';
import './DiscoveryDashboard.css';

type DiscoveryTabKey = 'PAGES' | 'ENDPOINTS' | 'SOURCE_CODE' | 'FORMS' | 'GRAPH' | 'COVERAGE';

export default function DiscoveryDashboard() {
  const { scanId } = useParams();
  const navigate = useNavigate();

  const [activeTab, setActiveTab] = useState<DiscoveryTabKey>('ENDPOINTS');
  const [inventory, setInventory] = useState<UnifiedInventoryResponse | null>(null);
  const [scanStatus, setScanStatus] = useState<ScanStatusResponse | null>(null);
  const [graphData, setGraphData] = useState<GraphResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  // Graph interactive state
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1.0);
  const [pan, setPan] = useState({ x: 40, y: 40 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const graphContainerRef = useRef<HTMLDivElement>(null);

  const resolvedScanId = scanId || localStorage.getItem('last_active_scan_id') || 'latest';

  useEffect(() => {
    async function loadDiscoveryData() {
      setLoading(true);
      setError(null);
      try {
        const [invRes, statusRes, graphRes] = await Promise.allSettled([
          scanService.getScanInventory(resolvedScanId),
          scanService.getScanStatus(resolvedScanId),
          scanService.getScanGraph(resolvedScanId, 3)
        ]);

        if (invRes.status === 'fulfilled') {
          setInventory(invRes.value);
        } else {
          setError('Could not retrieve discovery inventory from database.');
        }

        if (statusRes.status === 'fulfilled') {
          setScanStatus(statusRes.value);
        }

        if (graphRes.status === 'fulfilled') {
          setGraphData(graphRes.value);
        }
      } catch (err: any) {
        setError(err.message || 'Error loading discovery data.');
      } finally {
        setLoading(false);
      }
    }
    loadDiscoveryData();
  }, [resolvedScanId]);

  // Derived 14 discovery metrics
  const metrics = useMemo(() => {
    if (!inventory || !inventory.assets) {
      return {
        pages: 0,
        frontendRoutes: 0,
        sourceDefined: 0,
        runtimeObserved: 0,
        apiEndpoints: 0,
        confirmedEndpoints: 0,
        sourceOnly: 0,
        runtimeOnly: 0,
        matchedEndpoints: 0,
        forms: 0,
        parameters: 0,
        graphqlOps: 0,
        websockets: 0,
        technologies: [] as string[]
      };
    }

    const assets = inventory.assets;

    let paramCount = 0;
    assets.forEach(a => {
      const metaParams = a.metadata_json?.parameters;
      if (Array.isArray(metaParams)) {
        paramCount += metaParams.length;
      } else if (typeof a.metadata_json?.parameter_count === 'number') {
        paramCount += a.metadata_json.parameter_count;
      }
    });

    const webTech = inventory.website_profile?.tech_stack || [];
    const repoFrameworks = inventory.repository_profile?.detected_frameworks || [];
    const allTech = Array.from(new Set([...webTech, ...repoFrameworks]));

    return {
      pages: assets.filter(a => a.asset_type === 'PAGE').length,
      frontendRoutes: assets.filter(a => a.asset_type === 'FRONTEND_ROUTE').length,
      sourceDefined: assets.filter(a => a.discovery_status === 'SOURCE_DEFINED' || a.source_evidences?.length > 0).length,
      runtimeObserved: assets.filter(a => a.discovery_status === 'RUNTIME_OBSERVED' || a.runtime_evidences?.length > 0).length,
      apiEndpoints: assets.filter(a => a.asset_type === 'HTTP_ENDPOINT' || a.asset_type === 'API_ENDPOINT').length,
      confirmedEndpoints: assets.filter(a => a.discovery_status === 'SOURCE_AND_RUNTIME_MATCH' || a.discovery_status === 'RUNTIME_CONFIRMED' || a.confidence >= 0.9).length,
      sourceOnly: assets.filter(a => a.discovery_status === 'SOURCE_ONLY').length,
      runtimeOnly: assets.filter(a => a.discovery_status === 'SHADOW_RUNTIME_ENDPOINT' || (a.discovery_status === 'RUNTIME_OBSERVED' && (!a.source_evidences || a.source_evidences.length === 0))).length,
      matchedEndpoints: assets.filter(a => a.discovery_status === 'SOURCE_AND_RUNTIME_MATCH').length,
      forms: assets.filter(a => a.asset_type === 'FORM').length,
      parameters: paramCount,
      graphqlOps: assets.filter(a => a.asset_type === 'GRAPHQL_OPERATION').length,
      websockets: assets.filter(a => a.asset_type === 'WEBSOCKET').length,
      technologies: allTech
    };
  }, [inventory]);

  // Tab Data Filters
  const pagesList = useMemo(() => {
    if (!inventory?.assets) return [];
    return inventory.assets.filter(a => a.asset_type === 'PAGE' && (
      !searchTerm || (a.url || a.path || a.name || '').toLowerCase().includes(searchTerm.toLowerCase())
    ));
  }, [inventory, searchTerm]);

  const endpointsList = useMemo(() => {
    if (!inventory?.assets) return [];
    return inventory.assets.filter(a => (a.asset_type === 'HTTP_ENDPOINT' || a.asset_type === 'API_ENDPOINT') && (
      !searchTerm || (a.path || a.url || a.identifier || '').toLowerCase().includes(searchTerm.toLowerCase())
    ));
  }, [inventory, searchTerm]);

  const sourceAssetsList = useMemo(() => {
    if (!inventory?.assets) return [];
    return inventory.assets.filter(a => a.source_evidences && a.source_evidences.length > 0 && (
      !searchTerm || (a.path || a.identifier || a.source_evidences[0]?.file_path || '').toLowerCase().includes(searchTerm.toLowerCase())
    ));
  }, [inventory, searchTerm]);

  const formsList = useMemo(() => {
    if (!inventory?.assets) return [];
    return inventory.assets.filter(a => (a.asset_type === 'FORM' || (a.metadata_json?.fields && a.metadata_json.fields.length > 0)) && (
      !searchTerm || (a.path || a.url || a.identifier || '').toLowerCase().includes(searchTerm.toLowerCase())
    ));
  }, [inventory, searchTerm]);

  // Graph drag handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    setIsDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging) return;
    setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
  };

  const handleMouseUp = () => setIsDragging(false);

  const getMethodBadgeClass = (method: string = 'GET') => {
    switch (method.toUpperCase()) {
      case 'GET': return 'method-get';
      case 'POST': return 'method-post';
      case 'PUT': return 'method-put';
      case 'DELETE': return 'method-delete';
      case 'PATCH': return 'method-patch';
      default: return 'method-get';
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'SOURCE_AND_RUNTIME_MATCH':
        return <span className="status-pill status-matched"><span className="material-symbols-outlined" style={{fontSize: '12px'}}>check_circle</span> Matched (Hybrid)</span>;
      case 'SOURCE_ONLY':
        return <span className="status-pill status-source-only"><span className="material-symbols-outlined" style={{fontSize: '12px'}}>code</span> Source Defined</span>;
      case 'RUNTIME_OBSERVED':
        return <span className="status-pill status-runtime-only"><span className="material-symbols-outlined" style={{fontSize: '12px'}}>public</span> Runtime Observed</span>;
      case 'SHADOW_RUNTIME_ENDPOINT':
        return <span className="status-pill status-shadow"><span className="material-symbols-outlined" style={{fontSize: '12px'}}>visibility_off</span> Shadow Route</span>;
      default:
        return <span className="status-pill">{status}</span>;
    }
  };

  return (
    <div className="discovery-container">
      {/* 1. Header */}
      <div className="discovery-header">
        <div className="discovery-header-left">
          <button type="button" className="btn-back" onClick={() => navigate(-1)} title="Back">
            <span className="material-symbols-outlined">arrow_back</span>
          </button>
          <div className="discovery-header-title">
            <h1>
              <span className="material-symbols-outlined text-primary">hub</span>
              Unified Discovery Intelligence
              <span className={`discovery-mode-badge ${
                inventory?.discovery_mode === 'HYBRID' ? 'badge-hybrid' :
                inventory?.discovery_mode === 'GITHUB_ONLY' ? 'badge-github' : 'badge-website'
              }`}>
                {inventory?.discovery_mode || 'WEBSITE_ONLY'}
              </span>
            </h1>
            <p style={{fontSize: '12px', color: 'var(--color-on-surface-variant)', margin: '4px 0 0 0'}}>
              Target: <b className="font-mono">{scanStatus?.target_url || scanStatus?.website_url || scanStatus?.repository_url || 'Target System'}</b>
              {' • '}Scan ID: <span className="font-mono">{resolvedScanId}</span>
            </p>
          </div>
        </div>

        <div className="discovery-header-actions">
          <button className="btn-outline-small" onClick={() => navigate(`/scans/${resolvedScanId}/attack-surface`)}>
            <span className="material-symbols-outlined" style={{fontSize: '16px'}}>account_tree</span>
            Dedicated Graph View
          </button>
          <button className="btn-outline-small" onClick={() => navigate(`/scans/${resolvedScanId}/progress`)}>
            <span className="material-symbols-outlined" style={{fontSize: '16px'}}>radar</span>
            Live Progress
          </button>
        </div>
      </div>

      {/* 2. 14 Discovery Metrics Bar */}
      <div className="discovery-metrics-bar">
        <div className="metric-card">
          <span className="metric-card-label">Pages</span>
          <span className="metric-card-val text-primary">{metrics.pages}</span>
        </div>
        <div className="metric-card">
          <span className="metric-card-label">Frontend Routes</span>
          <span className="metric-card-val">{metrics.frontendRoutes}</span>
        </div>
        <div className="metric-card">
          <span className="metric-card-label">Source Routes</span>
          <span className="metric-card-val" style={{color: '#a855f7'}}>{metrics.sourceDefined}</span>
        </div>
        <div className="metric-card">
          <span className="metric-card-label">Runtime Routes</span>
          <span className="metric-card-val" style={{color: '#00f0ff'}}>{metrics.runtimeObserved}</span>
        </div>
        <div className="metric-card">
          <span className="metric-card-label">API Endpoints</span>
          <span className="metric-card-val text-secondary">{metrics.apiEndpoints}</span>
        </div>
        <div className="metric-card">
          <span className="metric-card-label">Confirmed (Live)</span>
          <span className="metric-card-val" style={{color: '#10b981'}}>{metrics.confirmedEndpoints}</span>
        </div>
        <div className="metric-card">
          <span className="metric-card-label">Source-Only</span>
          <span className="metric-card-val">{metrics.sourceOnly}</span>
        </div>
        <div className="metric-card">
          <span className="metric-card-label">Runtime-Only</span>
          <span className="metric-card-val">{metrics.runtimeOnly}</span>
        </div>
        <div className="metric-card">
          <span className="metric-card-label">Matched (Hybrid)</span>
          <span className="metric-card-val" style={{color: '#10b981'}}>{metrics.matchedEndpoints}</span>
        </div>
        <div className="metric-card">
          <span className="metric-card-label">Forms</span>
          <span className="metric-card-val">{metrics.forms}</span>
        </div>
        <div className="metric-card">
          <span className="metric-card-label">Parameters</span>
          <span className="metric-card-val text-primary">{metrics.parameters}</span>
        </div>
        <div className="metric-card">
          <span className="metric-card-label">GraphQL Ops</span>
          <span className="metric-card-val">{metrics.graphqlOps}</span>
        </div>
        <div className="metric-card">
          <span className="metric-card-label">WebSockets</span>
          <span className="metric-card-val">{metrics.websockets}</span>
        </div>
        <div className="metric-card">
          <span className="metric-card-label">Technologies</span>
          <span className="metric-card-val" style={{fontSize: '14px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis'}}>
            {metrics.technologies.length > 0 ? metrics.technologies.join(', ') : 'None'}
          </span>
        </div>
      </div>

      {/* 3. Tab Navigation & Search */}
      <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--color-outline-variant)', marginBottom: '20px'}}>
        <div className="discovery-tabs-header" style={{borderBottom: 'none', marginBottom: 0}}>
          <button 
            className={`discovery-tab-btn ${activeTab === 'ENDPOINTS' ? 'active' : ''}`}
            onClick={() => setActiveTab('ENDPOINTS')}
          >
            <span className="material-symbols-outlined" style={{fontSize: '18px'}}>link</span>
            Endpoints <span className="tab-badge">{endpointsList.length}</span>
          </button>

          <button 
            className={`discovery-tab-btn ${activeTab === 'PAGES' ? 'active' : ''}`}
            onClick={() => setActiveTab('PAGES')}
          >
            <span className="material-symbols-outlined" style={{fontSize: '18px'}}>web</span>
            Pages <span className="tab-badge">{pagesList.length}</span>
          </button>

          <button 
            className={`discovery-tab-btn ${activeTab === 'SOURCE_CODE' ? 'active' : ''}`}
            onClick={() => setActiveTab('SOURCE_CODE')}
          >
            <span className="material-symbols-outlined" style={{fontSize: '18px'}}>code</span>
            Source Code <span className="tab-badge">{sourceAssetsList.length}</span>
          </button>

          <button 
            className={`discovery-tab-btn ${activeTab === 'FORMS' ? 'active' : ''}`}
            onClick={() => setActiveTab('FORMS')}
          >
            <span className="material-symbols-outlined" style={{fontSize: '18px'}}>dynamic_form</span>
            Forms & Parameters <span className="tab-badge">{formsList.length}</span>
          </button>

          <button 
            className={`discovery-tab-btn ${activeTab === 'GRAPH' ? 'active' : ''}`}
            onClick={() => setActiveTab('GRAPH')}
          >
            <span className="material-symbols-outlined" style={{fontSize: '18px'}}>account_tree</span>
            Attack Surface Graph
          </button>

          <button 
            className={`discovery-tab-btn ${activeTab === 'COVERAGE' ? 'active' : ''}`}
            onClick={() => setActiveTab('COVERAGE')}
          >
            <span className="material-symbols-outlined" style={{fontSize: '18px'}}>checklist</span>
            Coverage & Gaps
          </button>
        </div>

        {activeTab !== 'GRAPH' && activeTab !== 'COVERAGE' && (
          <div style={{display: 'flex', alignItems: 'center', gap: '8px', paddingBottom: '6px'}}>
            <span className="material-symbols-outlined text-muted" style={{fontSize: '18px'}}>search</span>
            <input 
              type="text" 
              className="form-input" 
              placeholder={`Search ${activeTab.toLowerCase()}...`}
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{width: '200px', height: '32px', fontSize: '12px'}}
            />
          </div>
        )}
      </div>

      {/* 4. Tab Content */}
      <div className="discovery-tab-content">
        {loading ? (
          <div className="state-box">
            <span className="material-symbols-outlined spin-icon text-primary" style={{fontSize: '36px'}}>sync</span>
            <h3>Loading discovery inventory...</h3>
          </div>
        ) : error ? (
          <div className="state-box">
            <span className="material-symbols-outlined text-error" style={{fontSize: '36px'}}>error</span>
            <h3>{error}</h3>
          </div>
        ) : (
          <>
            {/* TAB A: PAGES */}
            {activeTab === 'PAGES' && (
              <div className="discovery-table-wrapper">
                {pagesList.length === 0 ? (
                  <div className="state-box">
                    <span className="material-symbols-outlined">web_asset_off</span>
                    <h3>No discovered web pages found for this scan.</h3>
                  </div>
                ) : (
                  <table className="discovery-table">
                    <thead>
                      <tr>
                        <th>Page URL</th>
                        <th>Title</th>
                        <th>Status</th>
                        <th>Depth</th>
                        <th>Source</th>
                        <th>Auth Context</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pagesList.map((p) => (
                        <tr key={p.id}>
                          <td className="font-mono text-primary" style={{fontWeight: 600}}>
                            {p.url || p.path || p.identifier}
                          </td>
                          <td>{p.name || p.metadata_json?.title || '—'}</td>
                          <td>
                            <span className="font-mono" style={{
                              color: (p.metadata_json?.status_code || 200) < 400 ? 'var(--color-primary)' : 'var(--color-error)'
                            }}>
                              {p.metadata_json?.status_code || 200}
                            </span>
                          </td>
                          <td className="font-mono">Depth {p.metadata_json?.depth ?? 0}</td>
                          <td>{getStatusBadge(p.discovery_status)}</td>
                          <td>
                            {p.metadata_json?.auth_required ? (
                              <span style={{color: 'var(--color-tertiary)', display: 'flex', alignItems: 'center', gap: '4px'}}>
                                <span className="material-symbols-outlined" style={{fontSize: '14px'}}>lock</span> Authenticated
                              </span>
                            ) : (
                              <span style={{color: 'var(--color-on-surface-variant)'}}>Public</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}

            {/* TAB B: ENDPOINTS */}
            {activeTab === 'ENDPOINTS' && (
              <div className="discovery-table-wrapper">
                {endpointsList.length === 0 ? (
                  <div className="state-box">
                    <span className="material-symbols-outlined">link_off</span>
                    <h3>No HTTP/API endpoints discovered.</h3>
                  </div>
                ) : (
                  <table className="discovery-table">
                    <thead>
                      <tr>
                        <th>Method</th>
                        <th>Endpoint Path</th>
                        <th>Parameters</th>
                        <th>Content Type</th>
                        <th>Discovery Source</th>
                        <th>Lifecycle Status</th>
                        <th>Correlation</th>
                      </tr>
                    </thead>
                    <tbody>
                      {endpointsList.map((ep) => (
                        <tr key={ep.id}>
                          <td>
                            <span className={`method-badge ${getMethodBadgeClass(ep.method)}`}>
                              {ep.method || 'GET'}
                            </span>
                          </td>
                          <td className="font-mono" style={{fontWeight: 600}}>
                            {ep.path || ep.url || ep.identifier}
                          </td>
                          <td className="font-mono">
                            {ep.metadata_json?.parameters?.length || ep.metadata_json?.parameter_count || 0} params
                          </td>
                          <td className="font-mono" style={{fontSize: '12px', color: 'var(--color-on-surface-variant)'}}>
                            {ep.metadata_json?.content_type || 'application/json'}
                          </td>
                          <td>{getStatusBadge(ep.discovery_status)}</td>
                          <td>
                            <span className="font-mono" style={{fontSize: '11px', color: 'var(--color-primary)'}}>
                              {ep.metadata_json?.testing_lifecycle || 'DISCOVERED'}
                            </span>
                          </td>
                          <td>
                            {ep.discovery_status === 'SOURCE_AND_RUNTIME_MATCH' ? (
                              <span style={{color: '#10b981', fontWeight: 600}}>Live & Source Match</span>
                            ) : ep.discovery_status === 'SOURCE_ONLY' ? (
                              <span style={{color: '#a855f7'}}>Source Code AST</span>
                            ) : (
                              <span style={{color: '#00f0ff'}}>Runtime Live Traffic</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}

            {/* TAB C: SOURCE CODE */}
            {activeTab === 'SOURCE_CODE' && (
              <div className="discovery-table-wrapper">
                {sourceAssetsList.length === 0 ? (
                  <div className="state-box">
                    <span className="material-symbols-outlined">code_off</span>
                    <h3>No source code route evidences available. Run GITHUB_ONLY or HYBRID scan mode to extract AST routes.</h3>
                  </div>
                ) : (
                  <table className="discovery-table">
                    <thead>
                      <tr>
                        <th>Discovered Route</th>
                        <th>Repository / Branch</th>
                        <th>Source File</th>
                        <th>Line Range</th>
                        <th>Framework</th>
                        <th>Evidence / Code Snippet</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sourceAssetsList.map((sa) => {
                        const sev = sa.source_evidences[0];
                        return (
                          <tr key={sa.id}>
                            <td>
                              <span className={`method-badge ${getMethodBadgeClass(sa.method)}`} style={{marginRight: '6px'}}>
                                {sa.method || 'GET'}
                              </span>
                              <span className="font-mono" style={{fontWeight: 600}}>{sa.identifier || sa.path}</span>
                            </td>
                            <td>
                              <span className="font-mono" style={{fontSize: '12px'}}>
                                {inventory?.repository_profile?.branch || 'main'}
                              </span>
                              {inventory?.repository_profile?.commit_sha && (
                                <div style={{fontSize: '11px', color: 'var(--color-on-surface-variant)'}} className="font-mono">
                                  {inventory.repository_profile.commit_sha.slice(0, 8)}
                                </div>
                              )}
                            </td>
                            <td className="font-mono text-primary">{sev?.file_path || '—'}</td>
                            <td className="font-mono">
                              {sev?.line_start ? `L${sev.line_start}${sev.line_end ? `–L${sev.line_end}` : ''}` : '—'}
                            </td>
                            <td>
                              <span className="font-mono" style={{fontSize: '12px'}}>{sev?.rule_name || 'AST Parser'}</span>
                            </td>
                            <td style={{maxWidth: '320px'}}>
                              {sev?.snippet ? (
                                <div className="code-snippet-box">
                                  {sev.snippet}
                                </div>
                              ) : (
                                <span className="text-muted" style={{fontSize: '11px'}}>AST declaration parsed</span>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                )}
              </div>
            )}

            {/* TAB D: FORMS AND PARAMETERS */}
            {activeTab === 'FORMS' && (
              <div className="discovery-table-wrapper">
                {formsList.length === 0 ? (
                  <div className="state-box">
                    <span className="material-symbols-outlined">assignment_late</span>
                    <h3>No HTML forms or input parameter models discovered.</h3>
                  </div>
                ) : (
                  <table className="discovery-table">
                    <thead>
                      <tr>
                        <th>Method</th>
                        <th>Form Action / Endpoint</th>
                        <th>Field Names</th>
                        <th>Input Types</th>
                        <th>Validation Constraints</th>
                      </tr>
                    </thead>
                    <tbody>
                      {formsList.map((f) => {
                        const fields = f.metadata_json?.fields || f.metadata_json?.inputs || [];
                        return (
                          <tr key={f.id}>
                            <td>
                              <span className={`method-badge ${getMethodBadgeClass(f.method || 'POST')}`}>
                                {f.method || 'POST'}
                              </span>
                            </td>
                            <td className="font-mono text-primary" style={{fontWeight: 600}}>
                              {f.metadata_json?.action || f.url || f.path || f.identifier}
                            </td>
                            <td className="font-mono">
                              {fields.length > 0 ? (
                                fields.map((field: any, idx: number) => (
                                  <span key={idx} style={{
                                    display: 'inline-block',
                                    background: 'rgba(255,255,255,0.06)',
                                    padding: '2px 6px',
                                    borderRadius: '4px',
                                    marginRight: '4px',
                                    marginBottom: '4px'
                                  }}>
                                    {field.name || field.id || `field_${idx}`}
                                  </span>
                                ))
                              ) : (
                                <span className="text-muted">Standard form payload</span>
                              )}
                            </td>
                            <td className="font-mono" style={{fontSize: '12px', color: 'var(--color-on-surface-variant)'}}>
                              {fields.length > 0 ? (
                                fields.map((field: any) => field.type || 'text').join(', ')
                              ) : 'text'}
                            </td>
                            <td>
                              <span className="font-mono" style={{fontSize: '11px', color: 'var(--color-primary)'}}>
                                {f.metadata_json?.auth_required ? 'CSRF + Auth Required' : 'Public form submission'}
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                )}
              </div>
            )}

            {/* TAB E: ATTACK SURFACE GRAPH */}
            {activeTab === 'GRAPH' && (
              <div style={{
                height: '620px',
                background: 'var(--color-surface-container-lowest)',
                border: '1px solid var(--color-outline-variant)',
                borderRadius: '8px',
                position: 'relative',
                overflow: 'hidden'
              }}>
                <div style={{
                  position: 'absolute',
                  top: '12px',
                  right: '12px',
                  display: 'flex',
                  gap: '8px',
                  zIndex: 10
                }}>
                  <button className="btn-icon-control" onClick={() => setZoom(z => Math.min(2.0, z + 0.15))} title="Zoom In">
                    <span className="material-symbols-outlined">zoom_in</span>
                  </button>
                  <button className="btn-icon-control" onClick={() => setZoom(z => Math.max(0.4, z - 0.15))} title="Zoom Out">
                    <span className="material-symbols-outlined">zoom_out</span>
                  </button>
                  <button className="btn-icon-control" onClick={() => { setZoom(1.0); setPan({ x: 40, y: 40 }); }} title="Reset View">
                    <span className="material-symbols-outlined">refresh</span>
                  </button>
                </div>

                <div 
                  ref={graphContainerRef}
                  onMouseDown={handleMouseDown}
                  onMouseMove={handleMouseMove}
                  onMouseUp={handleMouseUp}
                  onMouseLeave={handleMouseUp}
                  style={{
                    width: '100%',
                    height: '100%',
                    cursor: isDragging ? 'grabbing' : 'grab',
                    overflow: 'hidden'
                  }}
                >
                  <div style={{
                    transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
                    transformOrigin: '0 0',
                    transition: isDragging ? 'none' : 'transform 0.1s ease-out',
                    minWidth: '1200px',
                    minHeight: '800px',
                    position: 'relative'
                  }}>
                    {/* Render graph nodes */}
                    {graphData?.nodes && graphData.nodes.length > 0 ? (
                      <div style={{display: 'flex', flexWrap: 'wrap', gap: '16px', padding: '24px'}}>
                        {graphData.nodes.map((node, i) => (
                          <div 
                            key={node.id}
                            onClick={() => setSelectedNodeId(node.id)}
                            style={{
                              background: selectedNodeId === node.id ? 'rgba(0,240,255,0.15)' : 'var(--color-surface-container-high)',
                              border: selectedNodeId === node.id ? '2px solid #00f0ff' : '1px solid var(--color-outline-variant)',
                              borderRadius: '6px',
                              padding: '10px 14px',
                              minWidth: '180px',
                              cursor: 'pointer'
                            }}
                          >
                            <div style={{display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px'}}>
                              <span className="material-symbols-outlined" style={{fontSize: '16px', color: 'var(--color-primary)'}}>
                                {node.type === 'TARGET' ? 'public' :
                                 node.type === 'ENDPOINT' ? 'link' :
                                 node.type === 'PARAMETER' ? 'data_object' :
                                 node.type === 'FRONTEND_ROUTE' ? 'alt_route' :
                                 node.type === 'FORM' ? 'dynamic_form' : 'hub'}
                              </span>
                              <span style={{fontSize: '10px', fontWeight: 700, color: 'var(--color-on-surface-variant)'}}>
                                {node.type}
                              </span>
                            </div>
                            <div className="font-mono" style={{fontSize: '12px', fontWeight: 600}}>
                              {node.label}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="state-box" style={{paddingTop: '180px'}}>
                        <span className="material-symbols-outlined" style={{fontSize: '48px'}}>hub</span>
                        <h3>No multi-layer graph relationships available.</h3>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* TAB F: COVERAGE AND GAPS */}
            {activeTab === 'COVERAGE' && (
              <div>
                {/* 1. Primary Evidence-Based Discovery Metrics */}
                <div className="coverage-grid">
                  <div className="coverage-card">
                    <h3><span className="material-symbols-outlined text-primary">web</span> Web Pages Coverage</h3>
                    <p>Discovered and crawled web pages across site perimeter.</p>
                    <div className="coverage-stat-big text-primary">
                      {inventory?.coverage_gaps?.pages_discovered ?? metrics.pages}
                    </div>
                    <div style={{fontSize: '12px', marginTop: '6px', color: 'var(--color-on-surface-variant)'}}>
                      Visited: <b style={{color: '#22c55e'}}>{inventory?.coverage_gaps?.pages_visited ?? metrics.pages}</b> • Failed: <b style={{color: '#ef4444'}}>{inventory?.coverage_gaps?.pages_failed ?? 0}</b>
                    </div>
                  </div>

                  <div className="coverage-card">
                    <h3><span className="material-symbols-outlined text-primary">api</span> Endpoints Inventory</h3>
                    <p>Discovered API operations & HTTP endpoints.</p>
                    <div className="coverage-stat-big text-primary">
                      {inventory?.coverage_gaps?.endpoints_discovered ?? metrics.apiEndpoints}
                    </div>
                    <div style={{fontSize: '12px', marginTop: '6px', color: 'var(--color-on-surface-variant)'}}>
                      Runtime: <b style={{color: '#38bdf8'}}>{inventory?.coverage_gaps?.runtime_observed_endpoints ?? metrics.runtimeObserved}</b> • Source-Only: <b style={{color: '#a855f7'}}>{inventory?.coverage_gaps?.source_only_endpoints ?? metrics.sourceOnly}</b> • Matched: <b style={{color: '#22c55e'}}>{inventory?.coverage_gaps?.matched_endpoints ?? metrics.matchedEndpoints}</b>
                    </div>
                  </div>

                  <div className="coverage-card">
                    <h3><span className="material-symbols-outlined text-tertiary">code</span> Source Code Files</h3>
                    <p>Repository files scanned for routes, controllers, and AST tokens.</p>
                    <div className="coverage-stat-big text-tertiary">
                      {inventory?.coverage_gaps?.source_files_inventoried ?? (inventory?.repository_profile?.total_files_analyzed || 0)}
                    </div>
                    <div style={{fontSize: '12px', marginTop: '6px', color: 'var(--color-on-surface-variant)'}}>
                      Analyzed: <b style={{color: '#22c55e'}}>{inventory?.coverage_gaps?.source_files_analyzed ?? (inventory?.repository_profile?.total_files_analyzed || 0)}</b> • Skipped: <b>{inventory?.coverage_gaps?.source_files_skipped ?? 0}</b> • Failed: <b style={{color: '#ef4444'}}>{inventory?.coverage_gaps?.source_files_failed ?? 0}</b>
                    </div>
                  </div>

                  <div className="coverage-card">
                    <h3><span className="material-symbols-outlined" style={{color: '#f59e0b'}}>dynamic_form</span> Forms & Parameters</h3>
                    <p>Inputs and structured request payloads extracted for fuzzing.</p>
                    <div className="coverage-stat-big" style={{color: '#f59e0b'}}>
                      {inventory?.coverage_gaps?.parameters_extracted ?? metrics.parameters}
                    </div>
                    <div style={{fontSize: '12px', marginTop: '6px', color: 'var(--color-on-surface-variant)'}}>
                      HTML/DOM Forms: <b>{inventory?.coverage_gaps?.forms_discovered ?? metrics.forms}</b> • Extracted Parameters: <b>{inventory?.coverage_gaps?.parameters_extracted ?? metrics.parameters}</b>
                    </div>
                  </div>
                </div>

                {/* 2. Subsystem Coverage Status Grid */}
                <div className="coverage-grid" style={{marginTop: '16px'}}>
                  <div className="coverage-card" style={{padding: '16px'}}>
                    <div style={{fontSize: '11px', textTransform: 'uppercase', color: 'var(--color-on-surface-variant)', letterSpacing: '0.05em'}}>Browser Crawling</div>
                    <div style={{fontSize: '16px', fontWeight: 600, marginTop: '4px', color: inventory?.coverage_gaps?.browser_discovery_status === 'COMPLETED' ? '#22c55e' : (inventory?.coverage_gaps?.browser_discovery_status === 'NOT_PERFORMED' ? 'var(--color-on-surface-variant)' : '#eab308')}}>
                      {inventory?.coverage_gaps?.browser_discovery_status || 'NOT_PERFORMED'}
                    </div>
                    <p style={{fontSize: '11px', margin: '4px 0 0 0'}}>Playwright DOM rendering & network interception.</p>
                  </div>

                  <div className="coverage-card" style={{padding: '16px'}}>
                    <div style={{fontSize: '11px', textTransform: 'uppercase', color: 'var(--color-on-surface-variant)', letterSpacing: '0.05em'}}>Source-Runtime Correlation</div>
                    <div style={{fontSize: '16px', fontWeight: 600, marginTop: '4px', color: inventory?.coverage_gaps?.correlation_status === 'COMPLETED' ? '#22c55e' : (inventory?.coverage_gaps?.correlation_status === 'NOT_PERFORMED' ? 'var(--color-on-surface-variant)' : '#eab308')}}>
                      {inventory?.coverage_gaps?.correlation_status || 'NOT_PERFORMED'}
                    </div>
                    <p style={{fontSize: '11px', margin: '4px 0 0 0'}}>Cross-correlating AST definitions with live traffic.</p>
                  </div>

                  <div className="coverage-card" style={{padding: '16px'}}>
                    <div style={{fontSize: '11px', textTransform: 'uppercase', color: 'var(--color-on-surface-variant)', letterSpacing: '0.05em'}}>Vulnerability Validation</div>
                    <div style={{fontSize: '16px', fontWeight: 600, marginTop: '4px', color: inventory?.coverage_gaps?.validation_status === 'COMPLETED' ? '#22c55e' : (inventory?.coverage_gaps?.validation_status === 'NOT_PERFORMED' ? 'var(--color-on-surface-variant)' : '#eab308')}}>
                      {inventory?.coverage_gaps?.validation_status || 'NOT_PERFORMED'}
                    </div>
                    <p style={{fontSize: '11px', margin: '4px 0 0 0'}}>Multi-stage evidence verification & false-positive triage.</p>
                  </div>

                  <div className="coverage-card" style={{padding: '16px'}}>
                    <div style={{fontSize: '11px', textTransform: 'uppercase', color: 'var(--color-on-surface-variant)', letterSpacing: '0.05em'}}>Discovery Errors Recorded</div>
                    <div style={{fontSize: '16px', fontWeight: 600, marginTop: '4px', color: (inventory?.coverage_gaps?.failed_attempts || 0) > 0 ? '#ef4444' : '#22c55e'}}>
                      {inventory?.coverage_gaps?.failed_attempts ?? 0} Subsystem Errors
                    </div>
                    <p style={{fontSize: '11px', margin: '4px 0 0 0'}}>Exceptions caught and logged with error triage.</p>
                  </div>
                </div>

                {/* 3. Coverage Analysis Notes & Lifecycle */}
                <div className="discovery-table-wrapper" style={{padding: '20px', marginTop: '16px'}}>
                  <h3 style={{fontSize: '14px', margin: '0 0 12px 0', display: 'flex', alignItems: 'center', gap: '8px'}}>
                    <span className="material-symbols-outlined text-muted">info</span>
                    Scan Coverage Notes & Gap Explanations
                  </h3>

                  <div style={{marginBottom: '16px', fontSize: '13px'}}>
                    <span className="text-muted">Lifecycle Status / Termination Reason: </span>
                    <b className="font-mono" style={{color: 'var(--color-primary)'}}>
                      {inventory?.coverage_gaps?.termination_reason || scanStatus?.status || 'Active / Completed'}
                    </b>
                  </div>

                  {inventory?.coverage_gaps?.coverage_notes && inventory.coverage_gaps.coverage_notes.length > 0 && (
                    <ul style={{margin: '0 0 16px 20px', padding: 0, fontSize: '13px', color: 'var(--color-on-surface-variant)'}}>
                      {inventory.coverage_gaps.coverage_notes.map((note, idx) => (
                        <li key={idx} style={{marginBottom: '4px'}}>{note}</li>
                      ))}
                    </ul>
                  )}

                  {inventory?.coverage_gaps?.errors && inventory.coverage_gaps.errors.length > 0 ? (
                    <table className="discovery-table">
                      <thead>
                        <tr>
                          <th>Component</th>
                          <th>Error Type</th>
                          <th>Message</th>
                          <th>Target / File</th>
                          <th>Timestamp</th>
                        </tr>
                      </thead>
                      <tbody>
                        {inventory.coverage_gaps.errors.map((err, idx) => (
                          <tr key={idx}>
                            <td className="font-mono text-tertiary">{err.component}</td>
                            <td className="font-mono text-error">{err.error_type}</td>
                            <td>{err.message}</td>
                            <td className="font-mono">{err.target_url || err.source_file || '—'}</td>
                            <td className="font-mono text-muted">{err.timestamp || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <div style={{fontSize: '12px', color: 'var(--color-on-surface-variant)'}}>
                      [✓] Zero unhandled pipeline errors. All active discovery subsystems executed cleanly.
                    </div>
                  )}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
