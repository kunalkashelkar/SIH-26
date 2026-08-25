import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { scanService } from '../services/api';
import './LiveScan.css';

export default function LiveScan() {
  const navigate = useNavigate();
  const { scanId } = useParams();
  const [seconds, setSeconds] = useState(0);
  const [logs, setLogs] = useState<string[]>(["[INFO] Waiting for scan to initialize..."]);
  const [progress, setProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState("Initializing");
  const [currentStage, setCurrentStage] = useState("Initialization");
  const [target, setTarget] = useState("Loading...");
  
  const terminalEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const pollInterval = setInterval(async () => {
      if (!scanId || scanId === 'demo') return;
      
      try {
        const data = await scanService.getScanStatus(scanId);
        setScanStatus(data.status);
        setProgress(data.progress);
        setCurrentStage(data.current_stage);
        setTarget(data.target_url);
        
        // Mock elapsed calculation if started_at exists
        if (data.started_at) {
            const start = new Date(data.started_at).getTime();
            const end = data.completed_at ? new Date(data.completed_at).getTime() : Date.now();
            setSeconds(Math.floor((end - start) / 1000));
        }

        if (data.status === "Complete" || data.status === "Cancelled") {
          clearInterval(pollInterval);
        }
      } catch (err) {
        console.error("Failed to fetch scan status", err);
      }
    }, 1000);

    return () => clearInterval(pollInterval);
  }, [scanId]);

  const handleCancel = async () => {
    if (!scanId || scanId === 'demo') return;
    try {
      await fetch(`/api/scans/${scanId}/cancel`, { method: 'POST' });
      setScanStatus("Cancelling...");
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

  const formatLogClass = (log: string) => {
    if (log.includes("[CRITICAL]") || log.includes("[ALERT]")) return "text-error";
    if (log.includes("[WARN]")) return "text-tertiary";
    if (log.includes("[SUCCESS]")) return "text-on-surface";
    if (log.includes("[INFO]")) return "text-primary";
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
            <h1 className="scan-id-title">SCAN #{scanId}</h1>
            <div className="scan-meta-row">
              <span className="scan-status-text">{scanStatus}</span>
              <span className="material-symbols-outlined meta-separator">circle</span>
              <span>Target: {target}</span>
              <span className="material-symbols-outlined meta-separator">circle</span>
              <span className="font-mono" style={{fontSize: '12px'}}>
                Elapsed: <span>{formatTime(seconds)}</span>
              </span>
            </div>
          </div>
        </div>
        
        <div className="scan-actions">
          <button className="btn-action btn-pause" onClick={handleCancel}>
            <span className="material-symbols-outlined" style={{fontSize: '18px'}}>pause</span> PAUSE
          </button>
          <button className="btn-action btn-stop" onClick={handleCancel}>
            <span className="material-symbols-outlined" style={{fontSize: '18px'}}>stop</span> STOP SCAN
          </button>
          <button className="btn-action btn-view" onClick={() => navigate(`/scans/${scanId || 'demo'}/attack-surface`)}>
            <span className="material-symbols-outlined" style={{fontSize: '18px'}}>visibility</span> VIEW SURFACE
          </button>
        </div>
      </div>

      <div className="scan-main-grid">
        
        {/* Intelligence Pipeline */}
        <div className="pipeline-card">
          <div className="pipeline-header">
            <h2>Intelligence Pipeline</h2>
          </div>
          <div className="pipeline-body">
            
            {/* Stage 1 */}
            <div className="pipeline-stage">
              <div className="stage-top">
                <span className="stage-name text-primary">
                  <span className="material-symbols-outlined" style={{fontSize: '18px'}}>{progress === 100 ? 'check_circle' : 'refresh'}</span>
                  Discovery & Scanning
                </span>
                <span className="stage-progress-text text-primary">{progress}%</span>
              </div>
              <div className="progress-bar-bg">
                <div className="progress-bar-fill bg-primary" style={{width: `${progress}%`}}></div>
              </div>
              <div className="stage-meta">
                <span>Real-time analysis</span>
                <span>{scanStatus}</span>
              </div>
            </div>



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
              <span className="terminal-status-text">Streaming</span>
            </div>
          </div>
          
          <div className="terminal-body">
            {logs.map((log, index) => (
              <div key={index} className={formatLogClass(log)}>
                {log}
              </div>
            ))}
            <div ref={terminalEndRef} />
          </div>
          
          <div className="terminal-fade-bottom"></div>
        </div>

      </div>
    </div>
  );
}
