import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { scanService, ScanLogItem, ScanStatistics, ScanStageItem } from '../services/api';
import './LiveScan.css';

const FALLBACK_STAGES = [
  { key: 'DISCOVERY', label: '1. Discovery (Crawling & Param Extraction)', pct: 20 },
  { key: 'CONTEXT', label: '2. Context (Attack Surface & Logic Graph)', pct: 40 },
  { key: 'FUZZING', label: '3. Fuzzing (Adaptive Payload Probing)', pct: 60 },
  { key: 'ANALYSIS', label: '4. Analysis (Response Divergence & Anomaly)', pct: 80 },
  { key: 'VALIDATION', label: '5. Validation (Targeted Retests & ML)', pct: 95 },
  { key: 'COMPLETE', label: '6. Complete (Audit & Compliance Report)', pct: 100 },
];

interface DiscoverySubtask {
  key: string;
  label: string;
  icon: string;
  applicableModes: string[];
  keywords: string[];
}

const DISCOVERY_SUBTASKS: DiscoverySubtask[] = [
  { key: 'fingerprint', label: 'Website Fingerprinting', icon: 'fingerprint', applicableModes: ['WEBSITE_ONLY', 'HYBRID'], keywords: ['fingerprint', 'tech stack', 'TechnologyFingerprinter'] },
  { key: 'sitemap', label: 'Sitemap & Robots Discovery', icon: 'lan', applicableModes: ['WEBSITE_ONLY', 'HYBRID'], keywords: ['sitemap', 'robots.txt', 'SitemapDiscoverer'] },
  { key: 'static_crawl', label: 'Static HTML Crawling', icon: 'travel_explore', applicableModes: ['WEBSITE_ONLY', 'HYBRID'], keywords: ['static', 'StaticHtmlCrawler', 'Static crawler'] },
  { key: 'browser_crawl', label: 'Browser Crawling & DOM', icon: 'devices', applicableModes: ['WEBSITE_ONLY', 'HYBRID'], keywords: ['browser', 'Playwright', 'dynamic crawl'] },
  { key: 'network_intercept', label: 'Network Interception', icon: 'swap_horiz', applicableModes: ['WEBSITE_ONLY', 'HYBRID'], keywords: ['network', 'intercept', 'API request'] },
  { key: 'js_analysis', label: 'JavaScript Bundle Analysis', icon: 'javascript', applicableModes: ['WEBSITE_ONLY', 'HYBRID'], keywords: ['JavaScript', 'JS bundle', 'bundle analysis'] },
  { key: 'repo_acq', label: 'GitHub Repository Acquisition', icon: 'download', applicableModes: ['GITHUB_ONLY', 'REPOSITORY_ONLY', 'HYBRID'], keywords: ['Acquiring repository', 'RepositoryDownloader', 'RepositoryAcquirer', 'ACQUISITION'] },
  { key: 'frontend_routes', label: 'Frontend Route Analysis', icon: 'alt_route', applicableModes: ['GITHUB_ONLY', 'REPOSITORY_ONLY', 'HYBRID'], keywords: ['frontend route', 'React Router', 'Next.js'] },
  { key: 'backend_api', label: 'Backend API & Controllers', icon: 'api', applicableModes: ['GITHUB_ONLY', 'REPOSITORY_ONLY', 'HYBRID'], keywords: ['FastAPI', 'Flask', 'Django', 'Backend route', 'controller'] },
  { key: 'schema_analysis', label: 'Schema & Validator Analysis', icon: 'schema', applicableModes: ['GITHUB_ONLY', 'REPOSITORY_ONLY', 'HYBRID'], keywords: ['schema', 'Pydantic', 'TypeScript interface'] },
  { key: 'static_security', label: 'Static Security Analysis (SAST)', icon: 'security', applicableModes: ['GITHUB_ONLY', 'REPOSITORY_ONLY', 'HYBRID'], keywords: ['STATIC_SECURITY', 'StaticSecurityAnalyzer', 'security candidate', 'SAST'] },
  { key: 'correlation', label: 'Source/Runtime Correlation', icon: 'compare_arrows', applicableModes: ['HYBRID'], keywords: ['correlat', 'CorrelationEngine', 'cross-reference'] },
  { key: 'inventory_gen', label: 'Attack Surface Inventory', icon: 'inventory_2', applicableModes: ['WEBSITE_ONLY', 'GITHUB_ONLY', 'REPOSITORY_ONLY', 'HYBRID'], keywords: ['inventory', 'Discovery stage completed', 'DiscoveredAsset', 'FILE_INVENTORY'] },
];

export default function LiveScan() {
  const navigate = useNavigate();
  const { scanId } = useParams();
  const [activeScanId, setActiveScanId] = useState<string>('');
  const [seconds, setSeconds] = useState(0);
  const [logs, setLogs] = useState<ScanLogItem[]>([]);
  const [progress, setProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState("INITIALIZING");
  const [currentStage, setCurrentStage] = useState("INITIALIZING");
  const [discoveryMode, setDiscoveryMode] = useState<string>("WEBSITE_ONLY");
  const [target, setTarget] = useState("Loading...");
  const [stats, setStats] = useState<ScanStatistics | null>(null);
  const [stages, setStages] = useState<ScanStageItem[]>([]);
  const [retryingStage, setRetryingStage] = useState<string | null>(null);
  const [expandedStages, setExpandedStages] = useState<Set<string>>(new Set());

  const [tasksSummary, setTasksSummary] = useState<{
    pending: number;
    processing: number;
    completed: number;
    failed: number;
    skipped: number;
  } | null>(null);
  const [moduleStatus, setModuleStatus] = useState<Record<string, any> | null>(null);
  
  const terminalEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let resolvedId = scanId || localStorage.getItem('last_active_scan_id') || 'latest';
    setActiveScanId(resolvedId);

    const fetchStatusAndLogs = async () => {
      try {
        const [statusData, logsData, statsData] = await Promise.all([
          scanService.getScanStatus(resolvedId).catch(() => null),
          scanService.getScanLogs(resolvedId).catch(() => []),
          scanService.getScanStatistics(resolvedId).catch(() => null)
        ]);

        if (statusData) {
          if (statusData.scan_id && statusData.scan_id !== resolvedId) {
            resolvedId = statusData.scan_id;
            setActiveScanId(statusData.scan_id);
          }
          setScanStatus(statusData.status);
          setProgress(statusData.progress || 0);
          setCurrentStage(statusData.current_stage || "INITIALIZING");
          if (statusData.discovery_mode) setDiscoveryMode(statusData.discovery_mode);
          setTarget(statusData.target_url || statusData.website_url || statusData.repository_url || "Unknown Target");
          if (statusData.tasks_summary) setTasksSummary(statusData.tasks_summary);
          if (statusData.module_status) setModuleStatus(statusData.module_status);
          if (statusData.stages && statusData.stages.length > 0) {
            setStages(statusData.stages);
          }

          if (statusData.started_at) {
            const start = new Date(statusData.started_at).getTime();
            const end = statusData.completed_at ? new Date(statusData.completed_at).getTime() : Date.now();
            setSeconds(Math.max(0, Math.floor((end - start) / 1000)));
          }
        }

        if (logsData && logsData.length > 0) {
          setLogs(logsData);
        }

        if (statsData) {
          setStats(statsData);
        }
      } catch (err) {
        console.warn("Live scan fetch warning:", err);
      }
    };

    fetchStatusAndLogs();
    const interval = setInterval(fetchStatusAndLogs, 1500);

    return () => clearInterval(interval);
  }, [scanId]);

  const handleCancel = async () => {
    if (!activeScanId) return;
    try {
      await scanService.cancelScan(activeScanId);
      setScanStatus("CANCELLED");
    } catch (e) {
      console.error(e);
    }
  };

  const handleRetryStage = async (stageName: string) => {
    if (!activeScanId || retryingStage) return;
    try {
      setRetryingStage(stageName);
      await scanService.retryStage(activeScanId, stageName);
      const updated = await scanService.getScanStatus(activeScanId);
      if (updated && updated.stages) {
        setStages(updated.stages);
      }
    } catch (err) {
      console.error("Failed to retry stage:", err);
    } finally {
      setRetryingStage(null);
    }
  };

  const toggleExpandStage = (stageName: string) => {
    const next = new Set(expandedStages);
    if (next.has(stageName)) {
      next.delete(stageName);
    } else {
      next.add(stageName);
    }
    setExpandedStages(next);
  };

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const formatTime = (totalSeconds: number) => {
    const mins = Math.floor(totalSeconds / 60).toString().padStart(2, '0');
    const secs = (totalSeconds % 60).toString().padStart(2, '0');
    return `${mins}:${secs}`;
  };

  const getLogClass = (level: string, message: string) => {
    const lvl = (level || '').toUpperCase();
    if (lvl === 'CRITICAL' || message.includes('ANOMALY') || message.includes('VULNERABILITY')) return "text-error";
    if (lvl === 'WARNING' || lvl === 'WARN') return "text-tertiary";
    if (lvl === 'INFO' && (message.includes('completed') || message.includes('Completed'))) return "text-on-surface";
    if (lvl === 'INFO') return "text-primary";
    return "text-muted";
  };

  const SUBTASK_TO_MODULE: Record<string, string> = {
    fingerprint: 'fingerprinting',
    sitemap: 'crawling',
    static_crawl: 'crawling',
    browser_crawl: 'browser_discovery',
    network_intercept: 'browser_discovery',
    js_analysis: 'browser_discovery',
    repo_acq: 'source_analysis',
    frontend_routes: 'source_analysis',
    backend_api: 'source_analysis',
    schema_analysis: 'source_analysis',
    correlation: 'correlating',
    inventory_gen: 'persisting',
  };

  const getSubtaskStatus = (task: DiscoverySubtask): { status: string; label: string; color: string; icon: string } => {
    if (!task.applicableModes.includes(discoveryMode)) {
      return { status: 'SKIPPED', label: 'N/A (Skipped)', color: 'var(--color-on-surface-variant)', icon: 'block' };
    }

    const modKey = SUBTASK_TO_MODULE[task.key];
    if (moduleStatus && modKey && moduleStatus[modKey]) {
      const mod = moduleStatus[modKey];
      if (mod.status === 'SKIPPED') {
        return { status: 'SKIPPED', label: 'Skipped', color: 'var(--color-on-surface-variant)', icon: 'block' };
      }
      if (mod.status === 'FAILED') {
        return { status: 'FAILED', label: 'Failed', color: 'var(--color-error)', icon: 'error' };
      }
      if (mod.status === 'COMPLETED') {
        const extra = mod.duration_seconds ? ` (${mod.duration_seconds}s)` : '';
        return { status: 'COMPLETED', label: `Completed${extra}`, color: 'var(--color-primary)', icon: 'check_circle' };
      }
      if (mod.status === 'RUNNING') {
        return { status: 'RUNNING', label: 'In Progress', color: '#00f0ff', icon: 'sync' };
      }
    }

    if (scanStatus === 'COMPLETED' || scanStatus === 'PARTIALLY_COMPLETED') {
      return { status: 'COMPLETED', label: 'Completed', color: 'var(--color-primary)', icon: 'check_circle' };
    }
    if (scanStatus === 'FAILED' && (currentStage === 'DISCOVERY' || currentStage === 'INITIALIZING')) {
      const failed = logs.some(l => l.level === 'CRITICAL' && task.keywords.some(k => l.message.toLowerCase().includes(k.toLowerCase())));
      if (failed) return { status: 'FAILED', label: 'Failed', color: 'var(--color-error)', icon: 'error' };
    }
    const hasSuccess = logs.some(l => (l.level === 'SUCCESS' || l.message.includes('completed') || l.message.includes('discovered') || l.message.includes('extracted')) && task.keywords.some(k => l.message.toLowerCase().includes(k.toLowerCase())));
    if (hasSuccess) {
      return { status: 'COMPLETED', label: 'Completed', color: 'var(--color-primary)', icon: 'check_circle' };
    }
    const hasActivity = logs.some(l => task.keywords.some(k => l.message.toLowerCase().includes(k.toLowerCase())));
    if (hasActivity || (currentStage === 'DISCOVERY' && task.key === 'fingerprint')) {
      return { status: 'RUNNING', label: 'In Progress', color: '#00f0ff', icon: 'sync' };
    }
    return { status: 'PENDING', label: 'Pending', color: 'rgba(255, 255, 255, 0.4)', icon: 'radio_button_unchecked' };
  };

  const getStageBadgeClass = (status: string) => {
    const s = (status || '').toUpperCase();
    if (s === 'COMPLETED') return 'badge-completed';
    if (s === 'RUNNING') return 'badge-running';
    if (s === 'FAILED') return 'badge-failed';
    if (s === 'BLOCKED') return 'badge-blocked';
    if (s === 'SKIPPED') return 'badge-skipped';
    return 'badge-pending';
  };

  return (
    <div className="live-scan-container">
      
      {/* Scan Header */}
      <div className="scan-progress-header">
        <div className="scan-info-group">
          <div className="scan-icon-container">
            <span className="material-symbols-outlined" style={{fontSize: '24px'}}>radar</span>
            {scanStatus === 'RUNNING' && <span className="scan-icon-dot ping"></span>}
            <span className="scan-icon-dot"></span>
          </div>
          <div>
            <h1 className="scan-id-title">SCAN #{activeScanId ? activeScanId.slice(0, 8) : 'ACTIVE'}</h1>
            <div className="scan-meta-row">
              <span className="scan-status-text" style={{
                color: scanStatus === 'COMPLETED' ? '#4caf50' : 
                       scanStatus === 'PARTIALLY_COMPLETED' ? '#facc15' : 
                       scanStatus === 'FAILED' ? '#f44336' : 'var(--color-tertiary)'
              }}>
                {scanStatus}
              </span>
              <span className="material-symbols-outlined meta-separator">circle</span>
              <span>Target: <b>{target}</b></span>
              <span className="material-symbols-outlined meta-separator">circle</span>
              <span className="font-mono" style={{fontSize: '12px'}}>
                Elapsed: <span>{formatTime(seconds)}</span>
              </span>
            </div>
          </div>
        </div>
        
        <div className="scan-actions">
          {scanStatus === 'RUNNING' || scanStatus === 'QUEUED' ? (
            <button className="btn-action btn-stop" onClick={handleCancel}>
              <span className="material-symbols-outlined" style={{fontSize: '18px'}}>stop</span> STOP SCAN
            </button>
          ) : null}
          <button 
            className="btn-action" 
            onClick={() => navigate(`/findings?scan_id=${activeScanId}`)}
            style={{
              background: 'rgba(88, 166, 255, 0.15)',
              border: '1px solid var(--color-primary)',
              color: 'var(--color-primary)',
              fontWeight: 700
            }}
          >
            <span className="material-symbols-outlined" style={{fontSize: '18px'}}>security</span>
            VIEW FINDINGS ({stats?.total_findings ?? 0})
          </button>
          <button className="btn-action btn-view" onClick={() => navigate(`/scans/${activeScanId}/discovery`)}>
            <span className="material-symbols-outlined" style={{fontSize: '18px'}}>inventory_2</span> INVENTORY
          </button>
          <button className="btn-action btn-view" onClick={() => navigate(`/scans/${activeScanId}/attack-surface`)}>
            <span className="material-symbols-outlined" style={{fontSize: '18px'}}>hub</span> ATTACK SURFACE
          </button>
          <button className="btn-action btn-view" onClick={() => navigate(`/scans/${activeScanId}/fuzzing`)}>
            <span className="material-symbols-outlined" style={{fontSize: '18px'}}>science</span> LIVE FUZZING
          </button>
        </div>
      </div>

      {/* Real-time Scan Telemetry Bar */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
        gap: '12px',
        marginBottom: '20px'
      }}>
        <div style={{padding: '12px 14px', background: 'var(--color-surface)', borderRadius: '6px', border: '1px solid var(--color-outline-variant)'}}>
          <div style={{fontSize: '11px', color: 'var(--color-on-surface-variant)', textTransform: 'uppercase'}}>Scan Mode</div>
          <div style={{fontSize: '14px', fontWeight: 700, marginTop: '2px', color: 'var(--color-on-surface)'}}>{discoveryMode}</div>
        </div>
        <div style={{padding: '12px 14px', background: 'var(--color-surface)', borderRadius: '6px', border: '1px solid var(--color-outline-variant)'}}>
          <div style={{fontSize: '11px', color: 'var(--color-on-surface-variant)', textTransform: 'uppercase'}}>Current Stage</div>
          <div style={{fontSize: '14px', fontWeight: 700, marginTop: '2px', color: 'var(--color-on-surface)'}}>{currentStage}</div>
        </div>
        <div style={{padding: '12px 14px', background: 'var(--color-surface)', borderRadius: '6px', border: '1px solid var(--color-outline-variant)'}}>
          <div style={{fontSize: '11px', color: 'var(--color-on-surface-variant)', textTransform: 'uppercase'}}>Progress</div>
          <div style={{fontSize: '14px', fontWeight: 700, marginTop: '2px', color: 'var(--color-primary)'}}>{progress}%</div>
        </div>
        <div style={{padding: '12px 14px', background: 'var(--color-surface)', borderRadius: '6px', border: '1px solid var(--color-outline-variant)'}}>
          <div style={{fontSize: '11px', color: 'var(--color-on-surface-variant)', textTransform: 'uppercase'}}>Discovered Assets</div>
          <div style={{fontSize: '14px', fontWeight: 700, marginTop: '2px', color: 'var(--color-secondary)'}}>{stats?.total_endpoints ?? '—'}</div>
        </div>
        <div style={{padding: '12px 14px', background: 'var(--color-surface)', borderRadius: '6px', border: '1px solid var(--color-outline-variant)'}}>
          <div style={{fontSize: '11px', color: 'var(--color-on-surface-variant)', textTransform: 'uppercase'}}>Requests Sent</div>
          <div style={{fontSize: '14px', fontWeight: 700, marginTop: '2px', color: 'var(--color-on-surface)'}}>{stats?.requests_performed?.toLocaleString() ?? '—'}</div>
        </div>
        <div style={{padding: '12px 14px', background: 'var(--color-surface)', borderRadius: '6px', border: '1px solid var(--color-outline-variant)'}}>
          <div style={{fontSize: '11px', color: 'var(--color-on-surface-variant)', textTransform: 'uppercase'}}>Persisted Findings</div>
          <div style={{fontSize: '14px', fontWeight: 700, marginTop: '2px', color: (stats?.total_findings || 0) > 0 ? 'var(--color-error)' : 'var(--color-on-surface)'}}>
            {stats?.total_findings ?? '0'}
          </div>
        </div>
      </div>

      {/* Partial Completion Alert */}
      {scanStatus === 'PARTIALLY_COMPLETED' && (
        <div style={{
          background: 'rgba(234, 179, 8, 0.12)',
          border: '1px solid rgba(234, 179, 8, 0.4)',
          borderRadius: '8px',
          padding: '12px 16px',
          marginBottom: '20px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          color: '#facc15'
        }}>
          <span className="material-symbols-outlined" style={{fontSize: '22px'}}>warning</span>
          <div style={{fontSize: '13px'}}>
            <b>Scan Partially Completed:</b> Some stages or independent submodules failed or were skipped during execution. All successfully collected assets and findings are preserved and viewable below.
          </div>
        </div>
      )}

      {/* Real Task Execution Counters (Zero Mock Data) */}
      {tasksSummary && (
        <div style={{
          background: 'var(--color-surface)',
          border: '1px solid var(--color-outline-variant)',
          borderRadius: '8px',
          padding: '12px 16px',
          marginBottom: '20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px'
        }}>
          <div style={{display: 'flex', alignItems: 'center', gap: '8px'}}>
            <span className="material-symbols-outlined text-secondary" style={{fontSize: '18px'}}>analytics</span>
            <span style={{fontSize: '12px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px'}}>
              Task Execution Counters:
            </span>
          </div>
          <div style={{display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap', fontSize: '12px'}}>
            <span style={{color: 'rgba(255,255,255,0.7)'}}>Pending: <b style={{color: '#fff'}}>{tasksSummary.pending}</b></span>
            <span style={{color: '#00f0ff'}}>Processing: <b>{tasksSummary.processing}</b></span>
            <span style={{color: 'var(--color-primary)'}}>Completed: <b>{tasksSummary.completed}</b></span>
            <span style={{color: 'var(--color-error)'}}>Failed: <b>{tasksSummary.failed}</b></span>
            <span style={{color: 'var(--color-on-surface-variant)'}}>Skipped: <b>{tasksSummary.skipped}</b></span>
          </div>
        </div>
      )}

      {/* Discovery Engine Subtasks Bar */}
      <div style={{
        background: 'var(--color-surface-container-lowest)',
        border: '1px solid var(--color-outline-variant)',
        borderRadius: '8px',
        padding: '16px 20px',
        marginBottom: '20px'
      }}>
        <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '8px'}}>
          <div style={{display: 'flex', alignItems: 'center', gap: '8px'}}>
            <span className="material-symbols-outlined text-primary" style={{fontSize: '20px'}}>travel_explore</span>
            <h3 style={{fontSize: '14px', fontWeight: 700, margin: 0}}>Discovery Subtasks Execution Status</h3>
            <span className="font-mono-sm" style={{fontSize: '11px', background: 'rgba(255,255,255,0.06)', padding: '2px 8px', borderRadius: '4px'}}>
              MODE: {discoveryMode}
            </span>
          </div>
          <button 
            type="button"
            className="btn-link font-caps text-primary"
            style={{fontSize: '11px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px'}}
            onClick={() => navigate(`/scans/${activeScanId}/discovery`)}
          >
            <span>View Full Inventory</span>
            <span className="material-symbols-outlined" style={{fontSize: '14px'}}>arrow_forward</span>
          </button>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '10px'
        }}>
          {DISCOVERY_SUBTASKS.map(task => {
            const taskInfo = getSubtaskStatus(task);
            return (
              <div 
                key={task.key}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '8px 12px',
                  background: 'var(--color-surface)',
                  border: '1px solid var(--color-outline-variant)',
                  borderRadius: '6px'
                }}
              >
                <div style={{display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0}}>
                  <span className="material-symbols-outlined" style={{fontSize: '16px', color: taskInfo.color}}>
                    {task.icon}
                  </span>
                  <span style={{fontSize: '12px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis'}}>
                    {task.label}
                  </span>
                </div>
                <div style={{display: 'flex', alignItems: 'center', gap: '4px', flexShrink: 0}}>
                  <span className={`material-symbols-outlined ${taskInfo.status === 'RUNNING' ? 'spin-icon' : ''}`} style={{fontSize: '13px', color: taskInfo.color}}>
                    {taskInfo.icon}
                  </span>
                  <span className="font-mono" style={{fontSize: '10px', color: taskInfo.color, fontWeight: 600}}>
                    {taskInfo.label}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="scan-main-grid">
        
        {/* Stage-by-Stage Intelligence Pipeline */}
        <div className="pipeline-card" style={{overflowY: 'auto', maxHeight: '560px'}}>
          <div className="pipeline-header" style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
            <h2>Pipeline Stages (Live Execution)</h2>
            <span style={{fontSize: '11px', color: 'var(--color-on-surface-variant)'}}>
              {stages.length > 0 ? `${stages.filter(s => s.stage_status === 'COMPLETED').length}/${stages.length} Completed` : ''}
            </span>
          </div>

          <div className="pipeline-body" style={{display: 'flex', flexDirection: 'column', gap: '10px', padding: '16px'}}>
            {stages.length > 0 ? (
              stages.map((stg) => {
                const isExpanded = expandedStages.has(stg.stage_name);
                const isRunning = stg.stage_status === 'RUNNING';
                const isFailed = stg.stage_status === 'FAILED';
                const isCompleted = stg.stage_status === 'COMPLETED';

                return (
                  <div key={stg.id || stg.stage_name} className="stage-item-card">
                    <div style={{display: 'flex', alignItems: 'center', justifyContent: 'space-between'}}>
                      <div 
                        style={{display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', flex: 1}}
                        onClick={() => toggleExpandStage(stg.stage_name)}
                      >
                        <span className="material-symbols-outlined" style={{
                          fontSize: '18px',
                          color: isCompleted ? '#4caf50' : isRunning ? '#00f0ff' : isFailed ? '#f44336' : 'var(--color-on-surface-variant)'
                        }}>
                          {isCompleted ? 'check_circle' : isRunning ? 'sync' : isFailed ? 'error' : 'radio_button_unchecked'}
                        </span>
                        <span style={{fontSize: '13px', fontWeight: isRunning ? 700 : 600, color: 'var(--color-on-surface)'}}>
                          {stg.stage_name.replace(/_/g, ' ')}
                        </span>
                        {stg.duration > 0 && (
                          <span style={{fontSize: '11px', color: 'var(--color-on-surface-variant)', fontFamily: 'monospace'}}>
                            ({stg.duration.toFixed(1)}s)
                          </span>
                        )}
                      </div>

                      <div style={{display: 'flex', alignItems: 'center', gap: '8px'}}>
                        <span className={`stage-status-badge ${getStageBadgeClass(stg.stage_status)}`}>
                          {stg.stage_status}
                        </span>
                        
                        {isFailed && (
                          <button 
                            className="btn-retry-stage"
                            onClick={() => handleRetryStage(stg.stage_name)}
                            disabled={retryingStage === stg.stage_name}
                          >
                            <span className="material-symbols-outlined" style={{fontSize: '13px'}}>refresh</span>
                            {retryingStage === stg.stage_name ? 'Retrying...' : 'Retry'}
                          </button>
                        )}

                        <span 
                          className="material-symbols-outlined" 
                          style={{fontSize: '16px', color: 'var(--color-on-surface-variant)', cursor: 'pointer'}}
                          onClick={() => toggleExpandStage(stg.stage_name)}
                        >
                          {isExpanded ? 'expand_less' : 'expand_more'}
                        </span>
                      </div>
                    </div>

                    {isFailed && stg.error_message && (
                      <div style={{
                        marginTop: '8px',
                        padding: '6px 10px',
                        borderRadius: '4px',
                        background: 'rgba(244, 67, 54, 0.1)',
                        border: '1px solid rgba(244, 67, 54, 0.25)',
                        fontSize: '11px',
                        color: '#ff8a80',
                        fontFamily: 'monospace'
                      }}>
                        <b>{stg.failure_category || 'ERROR'}:</b> {stg.error_message}
                      </div>
                    )}

                    {isExpanded && (
                      <div style={{
                        marginTop: '8px',
                        paddingTop: '8px',
                        borderTop: '1px solid rgba(255, 255, 255, 0.06)',
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(90px, 1fr))',
                        gap: '6px',
                        fontSize: '11px',
                        color: 'var(--color-on-surface-variant)'
                      }}>
                        <div>Input: <b style={{color: '#fff'}}>{stg.input_count ?? 0}</b></div>
                        <div>Processed: <b style={{color: '#fff'}}>{stg.processed_count ?? 0}</b></div>
                        <div>Output: <b style={{color: '#fff'}}>{stg.output_count ?? 0}</b></div>
                        <div>Retries: <b style={{color: '#fff'}}>{stg.retry_count ?? 0}</b></div>
                      </div>
                    )}
                  </div>
                );
              })
            ) : (
              FALLBACK_STAGES.map((stg) => {
                const isPast = progress > stg.pct;
                const isCurrent = currentStage.toUpperCase() === stg.key;
                const isComplete = progress === 100 || isPast;
                const stageColor = isComplete ? 'var(--color-secondary)' : isCurrent ? 'var(--color-primary)' : 'var(--color-on-surface-variant)';

                return (
                  <div key={stg.key} className="pipeline-stage">
                    <div className="stage-top" style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px'}}>
                      <span className="stage-name" style={{color: stageColor, display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', fontWeight: isCurrent ? 700 : 500}}>
                        <span className="material-symbols-outlined" style={{fontSize: '16px'}}>
                          {isComplete ? 'check_circle' : isCurrent ? 'refresh' : 'radio_button_unchecked'}
                        </span>
                        {stg.label}
                      </span>
                      <span className="stage-progress-text" style={{color: stageColor, fontSize: '12px', fontFamily: 'monospace'}}>
                        {isComplete ? '100%' : isCurrent ? `${progress}%` : 'Pending'}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Live Event Log */}
        <div className="terminal-card">
          <div className="terminal-header">
            <h2>
              <span className="material-symbols-outlined" style={{fontSize: '20px'}}>terminal</span> Live Event Log
            </h2>
            <div className="terminal-status">
              <span className="terminal-status-dot"></span>
              <span className="terminal-status-text">{scanStatus === 'RUNNING' ? 'Streaming' : scanStatus}</span>
            </div>
          </div>
          
          <div className="terminal-body" style={{fontFamily: 'monospace', fontSize: '12px', lineHeight: '1.6'}}>
            {logs.length === 0 ? (
              <div className="text-muted" style={{padding: '16px'}}>
                [INFO] Initializing scan executor and database event stream...
              </div>
            ) : (
              logs.map((log, index) => (
                <div key={log.id || index} className={getLogClass(log.level, log.message)} style={{padding: '2px 0'}}>
                  <span style={{color: 'var(--color-on-surface-variant)', marginRight: '8px'}}>
                    [{new Date(log.timestamp).toLocaleTimeString()}]
                  </span>
                  <span style={{fontWeight: 700, marginRight: '8px'}}>[{log.level}]</span>
                  <span>{log.message}</span>
                </div>
              ))
            )}
            <div ref={terminalEndRef} />
          </div>
          
          <div className="terminal-fade-bottom"></div>
        </div>

      </div>
    </div>
  );
}
