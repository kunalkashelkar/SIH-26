import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import './LiveScan.css';

export default function LiveScan() {
  const navigate = useNavigate();
  const { scanId } = useParams();
  const [seconds, setSeconds] = useState(154); // 02:34
  const [logs, setLogs] = useState<string[]>([
    "[INFO] Initializing scan #1042 for target: example.com...",
    "[INFO] Starting asset discovery phase...",
    "[SUCCESS] Found subdomain: dev.example.com",
    "[SUCCESS] Found subdomain: api.example.com",
    "[SUCCESS] Found subdomain: staging.example.com",
    "[WARN] WAF detected on api.example.com. Adjusting request rate.",
    "[INFO] Discovering endpoints on dev.example.com...",
    "[SUCCESS] Mapped endpoint: GET /api/v1/users",
    "[SUCCESS] Mapped endpoint: POST /api/v1/auth",
    "[INFO] Starting prioritization engine...",
    "[ALERT] Potential SQL Injection vector found on GET /api/v1/users?id=1",
    "[INFO] Fuzzing engine engaging target api.example.com...",
    "[DEBUG] Sending payload set: XSS_BASIC to POST /api/v1/auth",
    "[DEBUG] Received 403 Forbidden from WAF.",
    "[INFO] Adjusting fuzzing strategy..."
  ]);
  
  const terminalEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const timer = setInterval(() => {
      setSeconds(prev => prev + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const mockMessages = [
      "[DEBUG] Fuzzing parameter 'q' on search endpoint...",
      "[SUCCESS] Discovered exposed .git directory on staging.example.com.",
      "[CRITICAL] API key exposure detected in JS bundle.",
      "[INFO] Validating potential XSS finding...",
      "[WARN] High latency detected from target server. Backing off.",
      "[DEBUG] Sending request 8422...",
      "[SUCCESS] Found unauthenticated admin panel at /admin-console."
    ];

    const logTimer = setInterval(() => {
      const randomMsg = mockMessages[Math.floor(Math.random() * mockMessages.length)];
      setLogs(prev => [...prev, randomMsg]);
    }, 2500);

    return () => clearInterval(logTimer);
  }, []);

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
            <h1 className="scan-id-title">SCAN #1042</h1>
            <div className="scan-meta-row">
              <span className="scan-status-text">Running</span>
              <span className="material-symbols-outlined meta-separator">circle</span>
              <span>Target: example.com</span>
              <span className="material-symbols-outlined meta-separator">circle</span>
              <span className="font-mono" style={{fontSize: '12px'}}>
                Elapsed: <span>{formatTime(seconds)}</span>
              </span>
            </div>
          </div>
        </div>
        
        <div className="scan-actions">
          <button className="btn-action btn-pause">
            <span className="material-symbols-outlined" style={{fontSize: '18px'}}>pause</span> PAUSE
          </button>
          <button className="btn-action btn-stop">
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
                  <span className="material-symbols-outlined" style={{fontSize: '18px'}}>check_circle</span>
                  Discovery
                </span>
                <span className="stage-progress-text text-primary">100%</span>
              </div>
              <div className="progress-bar-bg">
                <div className="progress-bar-fill bg-primary" style={{width: '100%'}}></div>
              </div>
              <div className="stage-meta">
                <span>1,284 assets found</span>
                <span>Completed</span>
              </div>
            </div>

            {/* Stage 2 */}
            <div className="pipeline-stage">
              <div className="stage-top">
                <span className="stage-name text-tertiary">
                  <span className="material-symbols-outlined" style={{fontSize: '18px', animation: 'spin 2s linear infinite'}}>refresh</span>
                  Attack Surface
                </span>
                <span className="stage-progress-text text-tertiary">82%</span>
              </div>
              <div className="progress-bar-bg">
                <div className="progress-bar-fill bg-tertiary" style={{width: '82%'}}>
                  <div className="progress-shimmer"></div>
                </div>
              </div>
              <div className="stage-meta">
                <span>342 endpoints mapped</span>
                <span>In Progress</span>
              </div>
            </div>

            {/* Stage 3 */}
            <div className="pipeline-stage">
              <div className="stage-top">
                <span className="stage-name text-tertiary">
                  <span className="material-symbols-outlined" style={{fontSize: '18px', animation: 'spin 2s linear infinite'}}>refresh</span>
                  Prioritization
                </span>
                <span className="stage-progress-text text-tertiary">61%</span>
              </div>
              <div className="progress-bar-bg">
                <div className="progress-bar-fill bg-tertiary" style={{width: '61%'}}>
                  <div className="progress-shimmer"></div>
                </div>
              </div>
              <div className="stage-meta">
                <span>Analyzing vulnerabilities...</span>
                <span>In Progress</span>
              </div>
            </div>

            {/* Stage 4 */}
            <div className="pipeline-stage">
              <div className="stage-top">
                <span className="stage-name text-tertiary">
                  <span className="material-symbols-outlined" style={{fontSize: '18px', animation: 'spin 2s linear infinite'}}>refresh</span>
                  Fuzzing
                </span>
                <span className="stage-progress-text text-tertiary">42%</span>
              </div>
              <div className="progress-bar-bg">
                <div className="progress-bar-fill bg-tertiary" style={{width: '42%'}}>
                  <div className="progress-shimmer"></div>
                </div>
              </div>
              <div className="stage-meta">
                <span>8,421 requests sent</span>
                <span>In Progress</span>
              </div>
            </div>

            {/* Stage 5 */}
            <div className="pipeline-stage pending">
              <div className="stage-top">
                <span className="stage-name text-muted">
                  <span className="material-symbols-outlined" style={{fontSize: '18px'}}>pending</span>
                  Validation
                </span>
                <span className="stage-progress-text text-muted">0%</span>
              </div>
              <div className="progress-bar-bg">
                <div className="progress-bar-fill bg-muted" style={{width: '0%'}}></div>
              </div>
              <div className="stage-meta">
                <span>Waiting for previous stages</span>
                <span>Pending</span>
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
