import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { scanService, ScanLogItem, ScanStatistics } from '../services/api';
import './LiveScan.css';

const STAGES = [
  { key: 'DISCOVERY', label: '1. Discovery (Crawling & Param Extraction)', pct: 20 },
  { key: 'CONTEXT', label: '2. Context (Attack Surface & Logic Graph)', pct: 40 },
  { key: 'FUZZING', label: '3. Fuzzing (Adaptive Payload Probing)', pct: 60 },
  { key: 'ANALYSIS', label: '4. Analysis (Response Divergence & Anomaly)', pct: 80 },
  { key: 'VALIDATION', label: '5. Validation (Targeted Retests & ML)', pct: 95 },
  { key: 'COMPLETE', label: '6. Complete (Audit & Compliance Report)', pct: 100 },
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
  const [target, setTarget] = useState("Loading...");
  const [stats, setStats] = useState<ScanStatistics | null>(null);
  
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
          setTarget(statusData.target_url);

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

  return (
    <div className="live-scan-container">
      
      {/* Scan Header */}
      <div className="scan-progress-header">
        <div className="scan-info-group">
          <div className="scan-icon-container">
            <span className="material-symbols-outlined" style={{fontSize: '24px'}}>radar</span>
            <span className="scan-icon-dot ping"></span>
            <span className="scan-icon-dot"></span>
          </div>
          <div>
            <h1 className="scan-id-title">SCAN #{activeScanId ? activeScanId.slice(0, 8) : 'ACTIVE'}</h1>
            <div className="scan-meta-row">
              <span className="scan-status-text" style={{fontWeight: 700}}>{scanStatus}</span>
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
          <div style={{fontSize: '14px', fontWeight: 700, marginTop: '2px', color: 'var(--color-on-surface)'}}>Adaptive Fuzz</div>
        </div>
        <div style={{padding: '12px 14px', background: 'var(--color-surface)', borderRadius: '6px', border: '1px solid var(--color-outline-variant)'}}>
          <div style={{fontSize: '11px', color: 'var(--color-on-surface-variant)', textTransform: 'uppercase'}}>Configured Depth</div>
          <div style={{fontSize: '14px', fontWeight: 700, marginTop: '2px', color: 'var(--color-primary)'}}>Depth 3</div>
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
          <div style={{fontSize: '11px', color: 'var(--color-on-surface-variant)', textTransform: 'uppercase'}}>Endpoints Discovered</div>
          <div style={{fontSize: '14px', fontWeight: 700, marginTop: '2px', color: 'var(--color-secondary)'}}>{stats?.total_endpoints ?? '—'}</div>
        </div>
        <div style={{padding: '12px 14px', background: 'var(--color-surface)', borderRadius: '6px', border: '1px solid var(--color-outline-variant)'}}>
          <div style={{fontSize: '11px', color: 'var(--color-on-surface-variant)', textTransform: 'uppercase'}}>Requests Sent</div>
          <div style={{fontSize: '14px', fontWeight: 700, marginTop: '2px', color: 'var(--color-on-surface)'}}>{stats?.requests_performed?.toLocaleString() ?? '—'}</div>
        </div>
        <div style={{padding: '12px 14px', background: 'var(--color-surface)', borderRadius: '6px', border: '1px solid var(--color-outline-variant)'}}>
          <div style={{fontSize: '11px', color: 'var(--color-on-surface-variant)', textTransform: 'uppercase'}}>Findings</div>
          <div style={{fontSize: '14px', fontWeight: 700, marginTop: '2px', color: (stats?.total_findings || 0) > 0 ? 'var(--color-error)' : 'var(--color-on-surface)'}}>
            {stats?.total_findings ?? '0'}
          </div>
        </div>
      </div>

      <div className="scan-main-grid">
        
        {/* Intelligence Pipeline */}
        <div className="pipeline-card">
          <div className="pipeline-header">
            <h2>Intelligence Pipeline</h2>
          </div>
          <div className="pipeline-body" style={{display: 'flex', flexDirection: 'column', gap: '14px'}}>
            
            {STAGES.map((stg) => {
              const isPast = progress > stg.pct;
              const isCurrent = currentStage.toUpperCase() === stg.key || (progress >= stg.pct - 15 && progress <= stg.pct);
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
                  <div className="progress-bar-bg" style={{height: '4px', background: 'rgba(255,255,255,0.06)', borderRadius: '2px', overflow: 'hidden'}}>
                    <div 
                      className="progress-bar-fill" 
                      style={{
                        height: '100%',
                        background: stageColor,
                        width: isComplete ? '100%' : isCurrent ? `${progress}%` : '0%'
                      }}
                    ></div>
                  </div>
                </div>
              );
            })}

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
