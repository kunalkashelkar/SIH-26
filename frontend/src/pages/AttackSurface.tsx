import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { scanService, GraphResponse, GraphNode, EndpointPriorityResult } from '../services/api';
import './AttackSurface.css';

export default function AttackSurface() {
  const navigate = useNavigate();
  const { scanId } = useParams();
  
  const [graphData, setGraphData] = useState<GraphResponse | null>(null);
  const [priorities, setPriorities] = useState<EndpointPriorityResult[]>([]);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [filterType, setFilterType] = useState<string>('ALL');
  const [highlightPanel, setHighlightPanel] = useState(false);
  const [loading, setLoading] = useState(true);

  // Fetch graph and priorities
  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        let currentScanId = scanId || localStorage.getItem('last_active_scan_id') || 'latest';
        
        const [graphRes, priorityRes] = await Promise.allSettled([
          scanService.getScanGraph(currentScanId),
          scanService.getScanPriorities(currentScanId)
        ]);

        if (graphRes.status === 'fulfilled') {
          setGraphData(graphRes.value);
          if (graphRes.value.nodes.length > 0) {
            setSelectedNodeId(graphRes.value.nodes[0].id);
          }
        }
        if (priorityRes.status === 'fulfilled') {
          setPriorities(priorityRes.value);
        }
      } catch (err) {
        console.error('Failed to load attack surface data', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, [scanId]);

  // Layout node coordinates by tier/type
  const positionedNodes = useMemo(() => {
    if (!graphData || !graphData.nodes) return [];

    // Group nodes by column tiers
    const tiers: Record<string, GraphNode[]> = {
      TARGET: [],
      DOMAIN: [],
      SUBDOMAIN_VHOST_API: [],
      ENDPOINT: [],
      PARAMETER: [],
      FINDING: []
    };

    graphData.nodes.forEach(node => {
      if (node.type === 'TARGET') tiers.TARGET.push(node);
      else if (node.type === 'DOMAIN') tiers.DOMAIN.push(node);
      else if (node.type === 'SUBDOMAIN' || node.type === 'VIRTUAL_HOST' || node.type === 'API') tiers.SUBDOMAIN_VHOST_API.push(node);
      else if (node.type === 'ENDPOINT') tiers.ENDPOINT.push(node);
      else if (node.type === 'PARAMETER') tiers.PARAMETER.push(node);
      else if (node.type === 'FINDING') tiers.FINDING.push(node);
      else tiers.ENDPOINT.push(node);
    });

    const tierX: Record<string, number> = {
      TARGET: 8,
      DOMAIN: 22,
      SUBDOMAIN_VHOST_API: 38,
      ENDPOINT: 58,
      PARAMETER: 78,
      FINDING: 93
    };

    const nodePosMap = new Map<string, { node: GraphNode; x: number; y: number }>();

    Object.entries(tiers).forEach(([tierKey, nodeList]) => {
      const x = tierX[tierKey];
      const count = nodeList.length;
      nodeList.forEach((node, idx) => {
        // distribute vertically between 12% and 88%
        const y = count === 1 ? 50 : 12 + (idx / Math.max(count - 1, 1)) * 76;
        nodePosMap.set(node.id, { node, x, y });
      });
    });

    return Array.from(nodePosMap.values());
  }, [graphData]);

  const nodePositionLookup = useMemo(() => {
    const map = new Map<string, { x: number; y: number }>();
    positionedNodes.forEach(p => map.set(p.node.id, { x: p.x, y: p.y }));
    return map;
  }, [positionedNodes]);

  // Filtered nodes
  const visibleNodes = useMemo(() => {
    if (filterType === 'ALL') return positionedNodes;
    return positionedNodes.filter(p => p.node.type === filterType);
  }, [positionedNodes, filterType]);

  const selectedNode = useMemo(() => {
    if (!graphData || !selectedNodeId) return null;
    return graphData.nodes.find(n => n.id === selectedNodeId) || null;
  }, [graphData, selectedNodeId]);

  const selectedPriority = useMemo(() => {
    if (!selectedNode || selectedNode.type !== 'ENDPOINT') return null;
    const epId = selectedNode.metadata?.endpoint_id || selectedNode.id.replace('endpoint_', '');
    return priorities.find(p => p.endpoint_id === epId) || null;
  }, [selectedNode, priorities]);

  const handleNodeClick = (id: string) => {
    setSelectedNodeId(id);
    setHighlightPanel(true);
    setTimeout(() => setHighlightPanel(false), 300);
  };

  const getNodeIcon = (type: string) => {
    switch (type) {
      case 'TARGET': return 'public';
      case 'DOMAIN': return 'language';
      case 'SUBDOMAIN': return 'alt_route';
      case 'VIRTUAL_HOST': return 'dns';
      case 'API': return 'api';
      case 'ENDPOINT': return 'link';
      case 'PARAMETER': return 'data_object';
      case 'FINDING': return 'bug_report';
      default: return 'circle';
    }
  };

  const getNodeClass = (type: string, isSelected: boolean, isHighRisk: boolean) => {
    let base = 'graph-node';
    if (type === 'TARGET') base += ' node-root';
    else if (type === 'DOMAIN' || type === 'API') base += ' node-path node-path-active';
    else if (type === 'SUBDOMAIN') base += ' node-path';
    else if (type === 'ENDPOINT') base += isHighRisk ? ' node-vuln' : ' node-endpoint';
    else if (type === 'PARAMETER') base += ' node-param';
    return base;
  };

  // Header stats
  const stats = graphData?.stats || {
    total_nodes: graphData?.nodes?.length || 0,
    node_counts_by_type: {},
    total_edges: graphData?.edges?.length || 0
  };

  const nodeCounts = (stats.node_counts_by_type as Record<string, number>) || {};
  const endpointCount = nodeCounts['ENDPOINT'] || 0;
  const apiCount = nodeCounts['API'] || 0;
  const paramCount = nodeCounts['PARAMETER'] || 0;
  const nodeCount = stats.total_nodes || graphData?.nodes?.length || 0;

  const targetLabel = graphData?.nodes?.find(n => n.type === 'TARGET')?.metadata?.base_url || 'Target Assets';

  return (
    <div className="attack-surface-container">
      {/* Header */}
      <div className="as-header">
        <div className="as-header-left">
          <div className="as-header-title">
            <h1>{targetLabel}</h1>
            <p>Attack Surface Graph</p>
          </div>
          <div className="as-header-divider"></div>
          <div className="as-header-stats">
            <div className="as-stat-box">
              <span className="as-stat-label">Nodes</span>
              <span className="as-stat-value">{nodeCount}</span>
            </div>
            <div className="as-stat-box">
              <span className="as-stat-label">Endpoints</span>
              <span className="as-stat-value">{endpointCount}</span>
            </div>
            <div className="as-stat-box">
              <span className="as-stat-label">APIs</span>
              <span className="as-stat-value">{apiCount}</span>
            </div>
            <div className="as-stat-box">
              <span className="as-stat-label">Parameters</span>
              <span className="as-stat-value">{paramCount}</span>
            </div>
          </div>
        </div>
        
        <div className="as-header-actions">
          <button 
            className="btn-outline" 
            onClick={() => {
              const types = ['ALL', 'ENDPOINT', 'API', 'SUBDOMAIN', 'PARAMETER', 'FINDING'];
              const nextIdx = (types.indexOf(filterType) + 1) % types.length;
              setFilterType(types[nextIdx]);
            }}
          >
            <span className="material-symbols-outlined" style={{fontSize: '16px'}}>filter_list</span> 
            Filter: {filterType}
          </button>
          <button className="btn-outline" onClick={() => window.print()}>
            <span className="material-symbols-outlined" style={{fontSize: '16px'}}>download</span> Export
          </button>
        </div>
      </div>

      <div className="as-main">
        {/* Graph Area */}
        <div className="graph-area">
          {/* SVG Connector Lines */}
          <svg className="graph-svg">
            {graphData?.edges?.map((edge, idx) => {
              const sourcePos = nodePositionLookup.get(edge.source);
              const targetPos = nodePositionLookup.get(edge.target);
              if (!sourcePos || !targetPos) return null;

              return (
                <line
                  key={`${edge.source}-${edge.target}-${idx}`}
                  x1={`${sourcePos.x}%`}
                  y1={`${sourcePos.y}%`}
                  x2={`${targetPos.x}%`}
                  y2={`${targetPos.y}%`}
                  stroke="#30363D"
                  strokeWidth="1.5"
                  strokeDasharray={edge.relationship === 'DEFINES_ENDPOINT' ? '4' : undefined}
                />
              );
            })}
          </svg>

          <div className="graph-nodes">
            {visibleNodes.map(({ node, x, y }) => {
              const isSelected = selectedNodeId === node.id;
              const isHighRisk = (node.metadata?.priority_score || 0) >= 8;

              return (
                <div
                  key={node.id}
                  className={getNodeClass(node.type, isSelected, isHighRisk)}
                  style={{ top: `${y}%`, left: `${x}%` }}
                  onClick={() => handleNodeClick(node.id)}
                >
                  <div
                    className="node-icon-wrapper"
                    style={{
                      animation: isSelected ? 'pulse 2s infinite' : undefined,
                      borderColor: isSelected ? 'var(--color-primary)' : undefined
                    }}
                  >
                    <span 
                      className="material-symbols-outlined" 
                      style={{
                        fontSize: node.type === 'PARAMETER' ? '12px' : '18px',
                        color: isHighRisk ? 'var(--color-error)' : 'var(--color-primary)'
                      }}
                    >
                      {getNodeIcon(node.type)}
                    </span>
                  </div>
                  <span className="node-label">{node.label}</span>
                </div>
              );
            })}
          </div>

          <div className="graph-legend">
            <span className="legend-title">Legend</span>
            <div className="legend-item">
              <div className="legend-dot dot-target"></div>
              <span>Target / Domain</span>
            </div>
            <div className="legend-item">
              <div className="legend-dot dot-active"></div>
              <span>API / Subdomain</span>
            </div>
            <div className="legend-item">
              <div className="legend-dot dot-risk"></div>
              <span>High Risk / Priority</span>
            </div>
          </div>
        </div>

        {/* Details Panel */}
        <div 
          className={`details-panel ${highlightPanel ? 'bg-surface-container-low' : ''}`} 
          style={{backgroundColor: highlightPanel ? 'var(--color-surface-container-low)' : 'var(--color-surface-container-lowest)'}}
        >
          {selectedNode ? (
            <>
              <div className="panel-header">
                <div className="panel-title-row">
                  <span className="method-badge">{selectedNode.metadata?.method || selectedNode.type}</span>
                  <h2 className="endpoint-title">{selectedNode.label}</h2>
                </div>
                <div className="panel-meta-row">
                  {selectedPriority ? (
                    <span 
                      className="risk-badge"
                      style={{
                        color: selectedPriority.priority === 'CRITICAL' || selectedPriority.priority === 'HIGH' ? 'var(--color-error)' : 'var(--color-primary)'
                      }}
                    >
                      <span className="material-symbols-outlined" style={{fontSize: '14px'}}>warning</span> 
                      {selectedPriority.priority} (Score: {selectedPriority.score})
                    </span>
                  ) : (
                    <span className="meta-time">Type: {selectedNode.type}</span>
                  )}
                  {selectedNode.metadata?.status_code && (
                    <span className="meta-time">HTTP {selectedNode.metadata.status_code}</span>
                  )}
                </div>
              </div>

              <div className="panel-content">
                {/* Parameters Section */}
                {selectedNode.metadata?.parameters && selectedNode.metadata.parameters.length > 0 && (
                  <div>
                    <h3 className="panel-section-title">Parameters ({selectedNode.metadata.parameters.length})</h3>
                    <div className="param-list">
                      {selectedNode.metadata.parameters.map((param: string, pIdx: number) => (
                        <div key={pIdx} className="param-item">
                          <span className="param-name">?{param}</span>
                          <span className="param-type">user-controlled</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Priority Reasons */}
                {selectedPriority && selectedPriority.reasons.length > 0 && (
                  <div>
                    <h3 className="panel-section-title">Prioritization Rules</h3>
                    <div className="finding-card">
                      <div className="finding-header">
                        <span className="material-symbols-outlined text-error" style={{fontSize: '16px'}}>security</span>
                        <p className="finding-title">{selectedPriority.priority} Priority Assessment</p>
                      </div>
                      <div className="finding-body">
                        {selectedPriority.reasons.map((reason, rIdx) => (
                          <p key={rIdx} className="finding-desc">• {reason}</p>
                        ))}
                        <button className="btn-link" onClick={() => navigate('/findings')}>
                          View Findings <span className="material-symbols-outlined" style={{fontSize: '12px'}}>arrow_forward</span>
                        </button>
                      </div>
                    </div>
                  </div>
                )}

                {/* Metadata Details */}
                <div>
                  <h3 className="panel-section-title">Asset Attributes</h3>
                  <div className="timeline">
                    <div className="timeline-event">
                      <div className="timeline-dot timeline-dot-primary"></div>
                      <div className="timeline-content">
                        <p className="timeline-title">Discovered Source</p>
                        <p className="timeline-time">{selectedNode.metadata?.discovered_from || 'Crawler / OpenAPI'}</p>
                      </div>
                    </div>
                    {selectedNode.metadata?.url && (
                      <div className="timeline-event">
                        <div className="timeline-dot timeline-dot-secondary"></div>
                        <div className="timeline-content">
                          <p className="timeline-title muted">Full URL</p>
                          <p className="timeline-time">{selectedNode.metadata.url}</p>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

              </div>
            </>
          ) : (
            <div className="panel-content">
              <p className="text-muted">Select a node from the graph to inspect properties.</p>
            </div>
          )}
        </div>

      </div>
    </div>
  );
}

