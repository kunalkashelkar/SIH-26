import React, { useState, useEffect, useMemo, useRef } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  scanService,
  mlService,
  GraphResponse,
  GraphNode,
  EndpointPriorityResult,
  MLPredictResponse,
  ScanStatusResponse
} from '../services/api';
import './AttackSurface.css';

interface TreeGraphNode {
  id: string;
  label: string;
  subLabel?: string;
  type: string;
  depth: number;
  x: number;
  y: number;
  width: number;
  height: number;
  isExpanded: boolean;
  hasChildren: boolean;
  childCount: number;
  vulnerableCount: number;
  highRiskCount: number;
  rawNode?: GraphNode;
  isHighRisk?: boolean;
  isRoot?: boolean;
}

interface TreeGraphEdge {
  id: string;
  source: string;
  target: string;
  sourceX: number;
  sourceY: number;
  targetX: number;
  targetY: number;
  relationship: string;
  isHighRisk?: boolean;
}

export default function AttackSurface() {
  const navigate = useNavigate();
  const { scanId } = useParams();

  // Real Scan & State Metadata
  const [scanInfo, setScanInfo] = useState<ScanStatusResponse | null>(null);
  const [graphData, setGraphData] = useState<GraphResponse | null>(null);
  const [priorities, setPriorities] = useState<EndpointPriorityResult[]>([]);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [mlPrediction, setMlPrediction] = useState<MLPredictResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Manual Depth Configuration (Defaults to 3, fully interactive)
  const [selectedDepth, setSelectedDepth] = useState<number>(3);

  // Focus & View Modes
  const [focusMode, setFocusMode] = useState<'OVERVIEW' | 'VULNERABILITIES' | 'ATTACK_PATHS'>('OVERVIEW');
  const [presentationMode, setPresentationMode] = useState(false);

  // Interactive Scrollable / Pannable Canvas State
  const [zoom, setZoom] = useState<number>(1.0);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 30, y: 30 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const canvasContainerRef = useRef<HTMLDivElement>(null);

  // Search & Filters
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [filterMethod, setFilterMethod] = useState<string>('ALL'); // ALL, GET, POST, PUT, DELETE
  const [filterVulnOnly, setFilterVulnOnly] = useState<boolean>(false);

  // Branch Expansion State Map (Node ID -> isExpanded boolean)
  const [collapsedNodes, setCollapsedNodes] = useState<Record<string, boolean>>({});

  // 1. Fetch Real Data from FastAPI / PostgreSQL
  useEffect(() => {
    async function loadData() {
      setLoading(true);
      setError(null);
      try {
        const currentScanId = scanId || localStorage.getItem('last_active_scan_id') || 'latest';

        const [graphRes, priorityRes, scanStatusRes] = await Promise.allSettled([
          scanService.getScanGraph(currentScanId, selectedDepth),
          scanService.getScanPriorities(currentScanId),
          scanService.getScanStatus(currentScanId)
        ]);

        if (graphRes.status === 'fulfilled') {
          setGraphData(graphRes.value);
          if (graphRes.value.nodes.length > 0 && !selectedNodeId) {
            setSelectedNodeId(graphRes.value.nodes[0].id);
          }
        } else {
          setError('Unable to load attack graph.');
        }

        if (priorityRes.status === 'fulfilled') {
          setPriorities(priorityRes.value);
        }

        if (scanStatusRes.status === 'fulfilled') {
          setScanInfo(scanStatusRes.value);
        }
      } catch (err) {
        console.error('Failed to load attack surface data', err);
        setError('Unable to load attack graph.');
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, [scanId, selectedDepth]);

  // 2. Fetch Real ML prediction when an Endpoint node is selected
  useEffect(() => {
    if (!selectedNodeId || !graphData) {
      setMlPrediction(null);
      return;
    }
    const node = graphData.nodes.find(n => n.id === selectedNodeId);
    if (node && node.type === 'ENDPOINT') {
      const epId = node.metadata?.endpoint_id || node.id.replace('endpoint_', '');
      mlService.predictEndpoint(epId)
        .then(res => setMlPrediction(res))
        .catch(() => setMlPrediction(null));
    } else {
      setMlPrediction(null);
    }
  }, [selectedNodeId, graphData]);

  // 3. Build Adjacency Graph from Real Backend Data
  const adjacencyMap = useMemo(() => {
    if (!graphData || !graphData.nodes) return { children: new Map<string, string[]>(), parents: new Map<string, string>() };

    const children = new Map<string, string[]>();
    const parents = new Map<string, string>();

    graphData.edges.forEach(edge => {
      if (!children.has(edge.source)) children.set(edge.source, []);
      children.get(edge.source)!.push(edge.target);
      parents.set(edge.target, edge.source);
    });

    return { children, parents };
  }, [graphData]);

  // 4. Calculate Hierarchical Layout with Fixed Node Dimensions
  const layout = useMemo(() => {
    if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
      return { nodes: [], edges: [], canvasWidth: 1000, canvasHeight: 600 };
    }

    const targetNode = graphData.nodes.find(n => n.type === 'TARGET') || graphData.nodes[0];
    const nodeMap = new Map<string, GraphNode>();
    graphData.nodes.forEach(n => nodeMap.set(n.id, n));

    const renderedNodes: TreeGraphNode[] = [];
    const renderedEdges: TreeGraphEdge[] = [];

    const NODE_WIDTH = 220;
    const NODE_HEIGHT = 52;
    const HORIZONTAL_GAP = 120; // Gap between depth tiers
    const VERTICAL_GAP = 24;     // Gap between sibling nodes

    let maxTreeX = 600;
    let currentGlobalY = 30;

    // Recursive subtree positioner
    function positionSubtree(nodeId: string, currentDepth: number): { topY: number; bottomY: number; centerY: number } {
      const raw = nodeMap.get(nodeId);
      if (!raw) return { topY: currentGlobalY, bottomY: currentGlobalY, centerY: currentGlobalY };

      const isCollapsed = !!collapsedNodes[nodeId];
      const allChildrenIds = adjacencyMap.children.get(nodeId) || [];

      // Filter children according to depth and user filters
      const validChildrenIds = allChildrenIds.filter(childId => {
        const childRaw = nodeMap.get(childId);
        if (!childRaw) return false;

        // Depth restriction
        if (currentDepth >= selectedDepth) return false;

        // Vuln-only focus mode filter
        if (filterVulnOnly) {
          const isVulnChild = childRaw.type === 'FINDING' || priorities.some(p => (p.endpoint_id === childRaw.metadata?.endpoint_id || p.endpoint_id === childRaw.id.replace('endpoint_', '')) && (p.priority === 'CRITICAL' || p.priority === 'HIGH'));
          if (!isVulnChild && childRaw.type === 'ENDPOINT') return false;
        }

        // HTTP Method filter for endpoints
        if (filterMethod !== 'ALL' && childRaw.type === 'ENDPOINT') {
          const method = (childRaw.metadata?.method || 'GET').toUpperCase();
          if (method !== filterMethod) return false;
        }

        // Search query filter
        if (searchQuery) {
          const q = searchQuery.toLowerCase();
          const matches = childRaw.label.toLowerCase().includes(q) || (childRaw.metadata?.url || '').toLowerCase().includes(q);
          if (!matches && childRaw.type === 'ENDPOINT') return false;
        }

        return true;
      });

      const nodeX = 40 + currentDepth * (NODE_WIDTH + HORIZONTAL_GAP);
      maxTreeX = Math.max(maxTreeX, nodeX + NODE_WIDTH + 80);

      // Check risk priority for endpoints / findings
      const epId = raw.metadata?.endpoint_id || raw.id.replace('endpoint_', '');
      const priorityInfo = priorities.find(p => p.endpoint_id === epId);
      const isHighRisk = raw.type === 'FINDING' || priorityInfo?.priority === 'CRITICAL' || priorityInfo?.priority === 'HIGH';

      let centerY: number;
      let subtreeTopY = currentGlobalY;
      let subtreeBottomY = currentGlobalY;

      if (validChildrenIds.length === 0 || isCollapsed) {
        centerY = currentGlobalY + NODE_HEIGHT / 2;
        subtreeTopY = currentGlobalY;
        subtreeBottomY = currentGlobalY + NODE_HEIGHT;
        currentGlobalY += NODE_HEIGHT + VERTICAL_GAP;
      } else {
        const childCenters: number[] = [];
        const firstChildTop = currentGlobalY;

        validChildrenIds.forEach(childId => {
          const childPos = positionSubtree(childId, currentDepth + 1);
          childCenters.push(childPos.centerY);

          const childX = 40 + (currentDepth + 1) * (NODE_WIDTH + HORIZONTAL_GAP);
          renderedEdges.push({
            id: `edge_${nodeId}_${childId}`,
            source: nodeId,
            target: childId,
            sourceX: nodeX + NODE_WIDTH,
            sourceY: childPos.centerY,
            targetX: childX,
            targetY: childPos.centerY,
            relationship: 'CONNECTED_TO',
            isHighRisk: isHighRisk
          });
        });

        const lastChildBottom = currentGlobalY - VERTICAL_GAP;
        subtreeTopY = firstChildTop;
        subtreeBottomY = lastChildBottom;
        centerY = (childCenters[0] + childCenters[childCenters.length - 1]) / 2;
      }

      let subLabel = raw.type;
      if (raw.type === 'ENDPOINT') {
        subLabel = `${raw.metadata?.method || 'GET'} • Depth ${raw.metadata?.depth ?? currentDepth}`;
      } else if (raw.type === 'TARGET') {
        subLabel = 'Root Target';
      } else if (raw.type === 'DOMAIN' || raw.type === 'SUBDOMAIN') {
        subLabel = raw.metadata?.ip_address || 'Domain Asset';
      } else if (raw.type === 'FINDING') {
        subLabel = raw.metadata?.severity || 'VULNERABILITY';
      }

      renderedNodes.push({
        id: raw.id,
        label: raw.label,
        subLabel: subLabel,
        type: raw.type,
        depth: currentDepth,
        x: nodeX,
        y: centerY - NODE_HEIGHT / 2,
        width: NODE_WIDTH,
        height: NODE_HEIGHT,
        isExpanded: !isCollapsed,
        hasChildren: allChildrenIds.length > 0,
        childCount: allChildrenIds.length,
        vulnerableCount: 0,
        highRiskCount: isHighRisk ? 1 : 0,
        rawNode: raw,
        isHighRisk: isHighRisk,
        isRoot: raw.id === targetNode.id
      });

      return { topY: subtreeTopY, bottomY: subtreeBottomY, centerY };
    }

    positionSubtree(targetNode.id, 0);

    // Update edge sourceY to match actual computed parent node centers
    const nodeCenterMap = new Map<string, { x: number; y: number }>();
    renderedNodes.forEach(n => nodeCenterMap.set(n.id, { x: n.x + n.width, y: n.y + n.height / 2 }));

    renderedEdges.forEach(e => {
      const parentPos = nodeCenterMap.get(e.source);
      if (parentPos) {
        e.sourceY = parentPos.y;
      }
    });

    const canvasWidth = Math.max(maxTreeX + 160, 1200);
    const canvasHeight = Math.max(currentGlobalY + 60, 600);

    return { nodes: renderedNodes, edges: renderedEdges, canvasWidth, canvasHeight };
  }, [graphData, selectedDepth, collapsedNodes, priorities, filterVulnOnly, filterMethod, searchQuery, adjacencyMap]);

  // Branch expand / collapse
  const toggleNodeCollapse = (nodeId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setCollapsedNodes(prev => ({
      ...prev,
      [nodeId]: !prev[nodeId]
    }));
  };

  const expandAll = () => setCollapsedNodes({});

  const collapseAll = () => {
    const newCollapsed: Record<string, boolean> = {};
    layout.nodes.forEach(n => {
      if (n.hasChildren && !n.isRoot) {
        newCollapsed[n.id] = true;
      }
    });
    setCollapsedNodes(newCollapsed);
  };

  // Pan & Drag Handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.button !== 0) return;
    setIsDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging) return;
    setPan({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y
    });
  };

  const handleMouseUp = () => setIsDragging(false);

  const handleZoom = (delta: number) => {
    setZoom(prev => Math.min(Math.max(prev + delta, 0.4), 2.0));
  };

  const centerRoot = () => {
    setZoom(1.0);
    setPan({ x: 30, y: 80 });
  };

  const resetView = () => {
    setZoom(1.0);
    setPan({ x: 30, y: 30 });
  };

  // Node Selection & Inspection
  const selectedNode = useMemo(() => {
    if (!graphData || !selectedNodeId) return null;
    return graphData.nodes.find(n => n.id === selectedNodeId) || null;
  }, [graphData, selectedNodeId]);

  const selectedPriority = useMemo(() => {
    if (!selectedNode || selectedNode.type !== 'ENDPOINT') return null;
    const epId = selectedNode.metadata?.endpoint_id || selectedNode.id.replace('endpoint_', '');
    return priorities.find(p => p.endpoint_id === epId) || null;
  }, [selectedNode, priorities]);

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
      default: return 'hub';
    }
  };

  const targetLabel = graphData?.nodes?.find(n => n.type === 'TARGET')?.label || scanInfo?.target_url || 'Target System';

  return (
    <div className={`attack-surface-container ${presentationMode ? 'presentation-mode' : ''}`}>
      {/* 1. Header with Scan Configuration & Quick KPIs */}
      <header className="as-header">
        <div className="as-header-left">
          <div className="as-header-title">
            <h1>Attack Surface Intelligence Graph</h1>
            <p>Target: <span className="text-primary font-mono-sm">{targetLabel}</span> • Scan ID: <span className="font-mono-sm">{scanId || scanInfo?.scan_id || 'latest'}</span></p>
          </div>
          <div className="as-header-divider"></div>

          <div className="as-header-stats">
            <div className="as-stat-box">
              <span className="as-stat-label">Configured Depth</span>
              <span className="as-stat-value text-primary">Level {selectedDepth}</span>
            </div>
            <div className="as-stat-box">
              <span className="as-stat-label">Rendered Nodes</span>
              <span className="as-stat-value">{layout.nodes.length}</span>
            </div>
            <div className="as-stat-box">
              <span className="as-stat-label">Rendered Edges</span>
              <span className="as-stat-value">{layout.edges.length}</span>
            </div>
          </div>
        </div>

        <div className="as-header-actions">
          {/* Depth Controller Buttons */}
          <div className="depth-selector-group">
            <span className="depth-label">Depth:</span>
            {[1, 2, 3, 4, 5].map(d => (
              <button
                key={d}
                className={`btn-depth ${selectedDepth === d ? 'active' : ''}`}
                onClick={() => setSelectedDepth(d)}
                title={`Render up to Depth ${d}`}
              >
                {d}
              </button>
            ))}
          </div>

          {/* Focus Mode Tabs */}
          <div className="segmented-control">
            <button
              className={focusMode === 'OVERVIEW' ? 'active' : ''}
              onClick={() => { setFocusMode('OVERVIEW'); setFilterVulnOnly(false); }}
            >
              Overview
            </button>
            <button
              className={focusMode === 'VULNERABILITIES' ? 'active' : ''}
              onClick={() => { setFocusMode('VULNERABILITIES'); setFilterVulnOnly(true); }}
            >
              Vulnerabilities
            </button>
            <button
              className={focusMode === 'ATTACK_PATHS' ? 'active' : ''}
              onClick={() => { setFocusMode('ATTACK_PATHS'); expandAll(); }}
            >
              Attack Paths
            </button>
          </div>

          <button
            className={`btn-outline ${presentationMode ? 'btn-active' : ''}`}
            onClick={() => setPresentationMode(!presentationMode)}
            title="Toggle Fullscreen Presentation View"
          >
            <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>slideshow</span>
            {presentationMode ? 'Exit' : 'Presentation'}
          </button>
        </div>
      </header>

      {/* 2. Structured Layout: Graph Panel (Left) & Isolated Details Panel (Right) */}
      <div className="attack-surface-content">

        {/* Left Column: Graph Viewport Container */}
        <section className="graph-panel">
          {/* Graph Toolbar */}
          <div className="as-toolbar">
            <div className="as-toolbar-search">
              <span className="material-symbols-outlined search-icon">search</span>
              <input
                type="text"
                placeholder="Search domain, URL, endpoint (e.g. /api/users, GET)..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
              {searchQuery && (
                <button className="clear-search" onClick={() => setSearchQuery('')}>✕</button>
              )}
            </div>

            <div className="as-toolbar-filters">
              <select value={filterMethod} onChange={(e) => setFilterMethod(e.target.value)} className="select-filter">
                <option value="ALL">All HTTP Methods</option>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
              </select>

              <div className="filter-checkbox-group">
                <label>
                  <input
                    type="checkbox"
                    checked={filterVulnOnly}
                    onChange={(e) => setFilterVulnOnly(e.target.checked)}
                  />
                  High Risk Only
                </label>
              </div>
            </div>

            <div className="as-toolbar-controls">
              <button className="btn-icon-control" onClick={() => handleZoom(0.15)} title="Zoom In">
                <span className="material-symbols-outlined">zoom_in</span>
              </button>
              <button className="btn-icon-control" onClick={() => handleZoom(-0.15)} title="Zoom Out">
                <span className="material-symbols-outlined">zoom_out</span>
              </button>
              <button className="btn-icon-control" onClick={centerRoot} title="Center on Root">
                <span className="material-symbols-outlined">filter_center_focus</span>
              </button>
              <button className="btn-icon-control" onClick={resetView} title="Reset View">
                <span className="material-symbols-outlined">refresh</span>
              </button>
              <button className="btn-outline-small" onClick={expandAll} title="Expand All Branches">
                Expand All
              </button>
              <button className="btn-outline-small" onClick={collapseAll} title="Collapse All Branches">
                Collapse All
              </button>
            </div>
          </div>

          {/* Dedicated Graph Viewport (Controlled Scrollable Area) */}
          <div className="graph-viewport-wrapper">
            {loading ? (
              <div className="graph-state-container">
                <span className="material-symbols-outlined spin-icon" style={{ fontSize: '36px', color: 'var(--color-primary)' }}>sync</span>
                <p>Building attack graph for Depth {selectedDepth}...</p>
              </div>
            ) : error ? (
              <div className="graph-state-container">
                <span className="material-symbols-outlined" style={{ fontSize: '36px', color: 'var(--color-error)' }}>error</span>
                <p>{error}</p>
              </div>
            ) : layout.nodes.length === 0 ? (
              <div className="graph-state-container">
                <span className="material-symbols-outlined" style={{ fontSize: '36px', color: 'var(--color-on-surface-variant)' }}>account_tree</span>
                <p>No attack-surface relationships found for Depth {selectedDepth}.</p>
              </div>
            ) : (
              <div
                className="graph-area scrollable-canvas-viewport"
                ref={canvasContainerRef}
                onMouseDown={handleMouseDown}
                onMouseMove={handleMouseMove}
                onMouseUp={handleMouseUp}
                onMouseLeave={handleMouseUp}
                style={{ cursor: isDragging ? 'grabbing' : 'grab' }}
              >
                {/* Independent Scaled Canvas */}
                <div
                  className="graph-canvas-inner"
                  style={{
                    width: `${layout.canvasWidth}px`,
                    height: `${layout.canvasHeight}px`,
                    transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
                    transformOrigin: '0 0',
                    transition: isDragging ? 'none' : 'transform 0.12s ease-out'
                  }}
                >
                  {/* SVG Connecting Curves */}
                  <svg className="graph-svg-connections" width={layout.canvasWidth} height={layout.canvasHeight}>
                    <defs>
                      <linearGradient id="edgeGradHighRisk" x1="0%" y1="0%" x2="100%" y2="0%">
                        <stop offset="0%" stopColor="rgba(244, 67, 54, 0.4)" />
                        <stop offset="100%" stopColor="rgba(244, 67, 54, 0.95)" />
                      </linearGradient>
                      <linearGradient id="edgeGradStandard" x1="0%" y1="0%" x2="100%" y2="0%">
                        <stop offset="0%" stopColor="rgba(255, 255, 255, 0.08)" />
                        <stop offset="100%" stopColor="rgba(99, 219, 203, 0.35)" />
                      </linearGradient>
                    </defs>

                    {layout.edges.map(edge => {
                      const isHigh = edge.isHighRisk;
                      const dx = (edge.targetX - edge.sourceX) * 0.55;
                      const pathData = `M ${edge.sourceX} ${edge.sourceY} C ${edge.sourceX + dx} ${edge.sourceY}, ${edge.targetX - dx} ${edge.targetY}, ${edge.targetX} ${edge.targetY}`;

                      return (
                        <path
                          key={edge.id}
                          d={pathData}
                          fill="none"
                          stroke={isHigh ? 'url(#edgeGradHighRisk)' : 'url(#edgeGradStandard)'}
                          strokeWidth={isHigh ? 2.5 : 1.5}
                          strokeDasharray={isHigh ? '4 2' : undefined}
                        />
                      );
                    })}
                  </svg>

                  {/* Rendered Graph Nodes */}
                  <div className="graph-nodes-container">
                    {layout.nodes.map(node => {
                      const isSelected = selectedNodeId === node.id;
                      const isHigh = node.isHighRisk;
                      const isRoot = node.isRoot;

                      return (
                        <div
                          key={node.id}
                          className={`tree-node-card type-${node.type.toLowerCase()} ${isSelected ? 'selected' : ''} ${isHigh ? 'node-high-risk' : ''} ${isRoot ? 'node-root-distinct' : ''}`}
                          style={{
                            left: `${node.x}px`,
                            top: `${node.y}px`,
                            width: `${node.width}px`,
                            height: `${node.height}px`
                          }}
                          onClick={() => setSelectedNodeId(node.id)}
                        >
                          <div className="tree-node-icon-box">
                            <span className="material-symbols-outlined" style={{ fontSize: isRoot ? '20px' : '16px' }}>
                              {getNodeIcon(node.type)}
                            </span>
                          </div>

                          <div className="tree-node-text-content">
                            <span className="tree-node-title" title={node.label}>{node.label}</span>
                            {node.subLabel && <span className="tree-node-subtitle">{node.subLabel}</span>}
                          </div>

                          {node.hasChildren && (
                            <button
                              className="node-expand-toggle"
                              onClick={(e) => toggleNodeCollapse(node.id, e)}
                              title={node.isExpanded ? 'Collapse descendants' : 'Expand descendants'}
                            >
                              <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>
                                {node.isExpanded ? 'remove' : 'add'}
                              </span>
                            </button>
                          )}

                          {isHigh && (
                            <span className="node-risk-pill">!</span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Minimap Overlay */}
                <div className="graph-minimap-panel">
                  <div className="minimap-title">Topology (Depth {selectedDepth})</div>
                  <div className="minimap-screen">
                    {layout.nodes.map(n => (
                      <div
                        key={n.id}
                        className={`minimap-point ${n.isRoot ? 'point-root' : ''} ${n.isHighRisk ? 'point-vuln' : ''}`}
                        style={{
                          left: `${(n.x / layout.canvasWidth) * 100}%`,
                          top: `${(n.y / layout.canvasHeight) * 100}%`
                        }}
                      />
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </section>

        {/* Right Column: Independent Details & Findings Panel */}
        <aside className="details-panel">
          {selectedNode ? (
            <>
              <div className="panel-header">
                <div className="panel-title-row">
                  <span className="method-badge">{selectedNode.metadata?.method || selectedNode.type}</span>
                  <h2 className="endpoint-title" title={selectedNode.label}>{selectedNode.label}</h2>
                </div>
                <div className="panel-meta-row">
                  {selectedNode.type === 'FINDING' ? (
                    <span
                      className="risk-badge"
                      style={{
                        color: selectedNode.metadata?.severity === 'CRITICAL' || selectedNode.metadata?.severity === 'HIGH' ? 'var(--color-error)' : 'var(--color-primary)'
                      }}
                    >
                      <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>warning</span>
                      {selectedNode.metadata?.severity || 'VULNERABILITY'}
                    </span>
                  ) : selectedPriority ? (
                    <span
                      className="risk-badge"
                      style={{
                        color: selectedPriority.priority === 'CRITICAL' || selectedPriority.priority === 'HIGH' ? 'var(--color-error)' : 'var(--color-primary)'
                      }}
                    >
                      <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>warning</span>
                      {selectedPriority.priority} (Score: {selectedPriority.score})
                    </span>
                  ) : (
                    <span className="meta-time">Node Type: {selectedNode.type}</span>
                  )}
                  {selectedNode.metadata?.status_code && (
                    <span className="meta-time">HTTP {selectedNode.metadata.status_code}</span>
                  )}
                  {selectedNode.metadata?.depth !== undefined && (
                    <span className="meta-time">Depth: {selectedNode.metadata.depth}</span>
                  )}
                </div>
              </div>

              <div className="panel-content">
                {/* 1. Endpoint Specific Details */}
                {selectedNode.type === 'ENDPOINT' && (
                  <>
                    <div className="panel-section-block">
                      <h3 className="panel-section-title">Endpoint Specifications</h3>
                      <div style={{display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '12px'}}>
                        <div style={{display: 'flex', justifyContent: 'space-between', padding: '6px 10px', background: 'rgba(0,0,0,0.2)', borderRadius: '4px'}}>
                          <span className="text-muted">HTTP Method:</span>
                          <span style={{fontWeight: 700, color: 'var(--color-primary)'}}>{selectedNode.metadata?.method || 'GET'}</span>
                        </div>
                        <div style={{display: 'flex', justifyContent: 'space-between', padding: '6px 10px', background: 'rgba(0,0,0,0.2)', borderRadius: '4px'}}>
                          <span className="text-muted">Endpoint Type:</span>
                          <span>{selectedNode.metadata?.endpoint_type || 'REST API / Route'}</span>
                        </div>
                        <div style={{display: 'flex', justifyContent: 'space-between', padding: '6px 10px', background: 'rgba(0,0,0,0.2)', borderRadius: '4px'}}>
                          <span className="text-muted">Authentication:</span>
                          <span>{selectedNode.metadata?.auth_required ? 'Required (Auth Guard)' : 'Unauthenticated (Public)'}</span>
                        </div>
                        <div style={{display: 'flex', justifyContent: 'space-between', padding: '6px 10px', background: 'rgba(0,0,0,0.2)', borderRadius: '4px'}}>
                          <span className="text-muted">External Exposure:</span>
                          <span style={{color: selectedNode.metadata?.external_exposure ? '#ff9800' : '#4caf50'}}>
                            {selectedNode.metadata?.external_exposure ? 'Externally Exposed' : 'Internal Boundary'}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Parameters Section */}
                    {selectedNode.metadata?.parameters && selectedNode.metadata.parameters.length > 0 && (
                      <div className="panel-section-block">
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
                  </>
                )}

                {/* 2. Vulnerability Specific Details */}
                {selectedNode.type === 'FINDING' && (
                  <div className="panel-section-block">
                    <h3 className="panel-section-title">Vulnerability Assessment</h3>
                    <div style={{padding: '12px', background: 'rgba(244, 67, 54, 0.08)', borderRadius: '6px', border: '1px solid rgba(244, 67, 54, 0.2)'}}>
                      <div style={{display: 'flex', justifyContent: 'space-between', marginBottom: '8px'}}>
                        <strong style={{color: 'var(--color-on-surface)'}}>{selectedNode.label}</strong>
                        <span className={`severity-badge ${selectedNode.metadata?.severity === 'CRITICAL' ? 'sev-critical' : 'sev-high'}`}>
                          {selectedNode.metadata?.severity || 'CRITICAL'}
                        </span>
                      </div>
                      {selectedNode.metadata?.endpoint && (
                        <p style={{fontSize: '12px', color: 'var(--color-on-surface-variant)', marginBottom: '8px'}}>
                          Affected: <code className="font-mono">{selectedNode.metadata.endpoint}</code>
                        </p>
                      )}
                      {selectedNode.metadata?.evidence && (
                        <div style={{fontSize: '12px', background: 'rgba(0,0,0,0.3)', padding: '8px', borderRadius: '4px', marginBottom: '8px', fontFamily: 'monospace'}}>
                          Evidence: {selectedNode.metadata.evidence}
                        </div>
                      )}
                      {selectedNode.metadata?.remediation && (
                        <div style={{fontSize: '12px', color: '#4caf50', marginTop: '6px'}}>
                          Fix: {selectedNode.metadata.remediation}
                        </div>
                      )}
                      <button 
                        className="btn-link" 
                        style={{marginTop: '10px'}} 
                        onClick={() => navigate(selectedNode.metadata?.finding_id ? `/vulnerabilities/${selectedNode.metadata.finding_id}` : '/findings')}
                      >
                        Open Triage Report →
                      </button>
                    </div>
                  </div>
                )}

                {/* 3. Domain / Asset Node Details */}
                {(selectedNode.type === 'TARGET' || selectedNode.type === 'DOMAIN' || selectedNode.type === 'SUBDOMAIN') && (
                  <div className="panel-section-block">
                    <h3 className="panel-section-title">Host Asset Metadata</h3>
                    <div style={{display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '12px'}}>
                      <div style={{display: 'flex', justifyContent: 'space-between', padding: '6px 10px', background: 'rgba(0,0,0,0.2)', borderRadius: '4px'}}>
                        <span className="text-muted">Asset Class:</span>
                        <span>{selectedNode.type}</span>
                      </div>
                      {selectedNode.metadata?.ip_address && (
                        <div style={{display: 'flex', justifyContent: 'space-between', padding: '6px 10px', background: 'rgba(0,0,0,0.2)', borderRadius: '4px'}}>
                          <span className="text-muted">IP Address:</span>
                          <span className="font-mono">{selectedNode.metadata.ip_address}</span>
                        </div>
                      )}
                      <div style={{display: 'flex', justifyContent: 'space-between', padding: '6px 10px', background: 'rgba(0,0,0,0.2)', borderRadius: '4px'}}>
                        <span className="text-muted">Discovery Source:</span>
                        <span>{selectedNode.metadata?.discovery_source || 'DNS / Crawler'}</span>
                      </div>
                    </div>
                  </div>
                )}

                {/* 4. Prioritization Rules Section */}
                {selectedPriority && selectedPriority.reasons.length > 0 && (
                  <div className="panel-section-block">
                    <h3 className="panel-section-title">Prioritization Rules</h3>
                    <div className="finding-card">
                      <div className="finding-header">
                        <span className="material-symbols-outlined text-error" style={{ fontSize: '16px' }}>security</span>
                        <p className="finding-title">{selectedPriority.priority} Priority Assessment</p>
                      </div>
                      <div className="finding-body">
                        {selectedPriority.reasons.map((reason, rIdx) => (
                          <p key={rIdx} className="finding-desc">• {reason}</p>
                        ))}
                        <button className="btn-link" onClick={() => navigate('/findings')}>
                          View Findings <span className="material-symbols-outlined" style={{ fontSize: '12px' }}>arrow_forward</span>
                        </button>
                      </div>
                    </div>
                  </div>
                )}

                {/* 5. Real XGBoost ML Classification */}
                {mlPrediction && (
                  <div className="panel-section-block">
                    <h3 className="panel-section-title" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span className="material-symbols-outlined" style={{ fontSize: '16px', color: '#9c27b0' }}>psychology</span>
                      XGBoost ML Classification
                    </h3>
                    <div style={{ padding: '14px', background: 'rgba(0,0,0,0.25)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.06)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                        <span style={{ fontSize: '12px', color: 'var(--color-on-surface-variant)' }}>ML Verdict:</span>
                        <span style={{
                          fontSize: '11px',
                          fontWeight: 700,
                          padding: '2px 8px',
                          borderRadius: '4px',
                          background: mlPrediction.prediction === 1 ? 'rgba(244, 67, 54, 0.15)' : 'rgba(76, 175, 80, 0.15)',
                          color: mlPrediction.prediction === 1 ? '#f44336' : '#4caf50'
                        }}>
                          {mlPrediction.label.toUpperCase()}
                        </span>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                        <span style={{ fontSize: '12px', color: 'var(--color-on-surface-variant)' }}>Vulnerability Probability:</span>
                        <span style={{ fontSize: '14px', fontWeight: 700, color: mlPrediction.prediction === 1 ? '#f44336' : '#4caf50' }}>
                          {(mlPrediction.vulnerable_probability * 100).toFixed(1)}%
                        </span>
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--color-on-surface-variant)', borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: '6px', marginTop: '6px' }}>
                        Trained on 27 Preprocessed Features • ROC-AUC: 0.996
                      </div>
                    </div>
                  </div>
                )}

                {/* 6. Asset Attributes Section */}
                <div className="panel-section-block">
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
                          <p className="timeline-time font-mono-sm break-all">{selectedNode.metadata.url}</p>
                        </div>
                      </div>
                    )}
                    {selectedNode.metadata?.cwe && (
                      <div className="timeline-event">
                        <div className="timeline-dot timeline-dot-error"></div>
                        <div className="timeline-content">
                          <p className="timeline-title muted">CWE Classification</p>
                          <p className="timeline-time font-mono-sm">{selectedNode.metadata.cwe}</p>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

              </div>
            </>
          ) : (
            <div className="panel-content" style={{ padding: '32px 16px', textAlign: 'center' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '36px', color: 'var(--color-on-surface-variant)', marginBottom: '8px' }}>touch_app</span>
              <p className="text-muted">Select any endpoint, domain, or finding node to inspect live attributes and ML risk factors.</p>
            </div>
          )}
        </aside>

      </div>
    </div>
  );
}
