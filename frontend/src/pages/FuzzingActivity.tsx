import React, { useState, useEffect, useRef } from 'react';
import { useParams } from 'react-router-dom';
import { scanService, FuzzResultItem, ScanStatistics } from '../services/api';
import './FuzzingActivity.css';

export default function FuzzingActivity() {
  const { scanId } = useParams();
  const [fuzzResults, setFuzzResults] = useState<FuzzResultItem[]>([]);
  const [stats, setStats] = useState<ScanStatistics | null>(null);
  const [activeScanId, setActiveScanId] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const streamRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    async function loadFuzzingData() {
      try {
        setLoading(true);
        let currentId = scanId || localStorage.getItem('last_active_scan_id');
        if (!currentId) {
          const scanList = await scanService.getScans(1).catch(() => []);
          if (scanList.length > 0) currentId = scanList[0].id;
        }
        
        if (currentId) {
          setActiveScanId(currentId);
          const [fuzzList, scanStats] = await Promise.all([
            scanService.getScanFuzzResults(currentId).catch(() => []),
            scanService.getScanStatistics(currentId).catch(() => null)
          ]);
          setFuzzResults(fuzzList);
          setStats(scanStats);
        }
      } catch (err) {
        console.warn("Fuzzing data fetch error:", err);
      } finally {
        setLoading(false);
      }
    }
    loadFuzzingData();

    // Live poll if active
    const interval = setInterval(async () => {
      const currentId = scanId || localStorage.getItem('last_active_scan_id');
      if (currentId) {
        try {
          const list = await scanService.getScanFuzzResults(currentId);
          setFuzzResults(list);
        } catch {}
      }
    }, 3000);

    return () => clearInterval(interval);
  }, [scanId]);

  const totalRequests = stats ? stats.requests_performed : fuzzResults.length;
  const anomaliesCount = fuzzResults.filter(f => f.anomaly_detected).length;
  const activePayloadsCount = fuzzResults.length;

  // Category distribution
  const categoryCounts: Record<string, number> = {};
  fuzzResults.forEach(f => {
    categoryCounts[f.category] = (categoryCounts[f.category] || 0) + 1;
  });

  const totalFuzzCount = fuzzResults.length || 1;
  const sqliPct = Math.round(((categoryCounts['SQLI'] || 0) / totalFuzzCount) * 100);
  const xssPct = Math.round(((categoryCounts['XSS'] || 0) / totalFuzzCount) * 100);
  const idorPct = Math.round(((categoryCounts['IDOR'] || 0) / totalFuzzCount) * 100);
  const traversalPct = Math.round(((categoryCounts['OPEN_REDIRECT'] || 0) / totalFuzzCount) * 100);
  const otherPct = Math.max(100 - (sqliPct + xssPct + idorPct + traversalPct), 0);

  const getCodeClass = (code?: number) => {
    if (!code) return '';
    if (code >= 500) return 'code-500';
    if (code >= 400) return 'code-400';
    if (code >= 200 && code < 300) return 'code-200';
    return '';
  };

  const latestTest = fuzzResults.length > 0 ? fuzzResults[0] : null;

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
            {totalRequests.toLocaleString()} <span className="stat-sub text-primary">Live</span>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-glow" style={{backgroundColor: 'rgba(193, 199, 208, 0.1)'}}></div>
          <div className="stat-header">
            <span className="stat-title">Payloads Tested</span>
            <span className="material-symbols-outlined text-secondary">category</span>
          </div>
          <div className="stat-value text-on-surface">
            {activePayloadsCount} <span className="stat-sub text-secondary">Probes</span>
          </div>
        </div>

        <div className="stat-card" style={{boxShadow: '0 10px 15px -3px rgba(255, 186, 66, 0.1)'}}>
          <div className="stat-glow" style={{backgroundColor: 'rgba(255, 186, 66, 0.1)'}}></div>
          <div className="stat-header">
            <span className="stat-title" style={{color: 'var(--color-tertiary)'}}>Anomalies Detected</span>
            <span className="material-symbols-outlined text-tertiary">warning</span>
          </div>
          <div className="stat-value" style={{color: 'var(--color-tertiary)'}}>
            {anomaliesCount} <span className="stat-sub" style={{opacity: 0.7}}>Validated in DB</span>
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
                Priority: Adaptive
              </span>
            </div>

            <div className="target-info">
              <div className="info-label">Endpoint</div>
              <div className="endpoint-display">
                <span className="method-tag">SCAN</span>
                <span className="endpoint-path">{latestTest?.endpoint_path || (stats?.target_url || '/api/v1')}</span>
              </div>
            </div>

            <div className="info-grid">
              <div className="info-box">
                <div className="box-label">Target Parameter</div>
                <div className="box-value">{latestTest?.parameter_name || 'All Discovered'}</div>
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
          <h3 className="dist-title">Payload Distribution ({fuzzResults.length} probes)</h3>
          <div className="dist-list">
            
            <div className="dist-item">
              <div className="dist-row">
                <span className="dist-name">SQL Injection</span>
                <span className="dist-pct">{sqliPct}%</span>
              </div>
              <div className="dist-bar-bg">
                <div className="dist-bar-fill bg-primary" style={{width: `${Math.max(sqliPct, 5)}%`}}></div>
              </div>
            </div>

            <div className="dist-item">
              <div className="dist-row">
                <span className="dist-name">Cross-Site Scripting</span>
                <span className="dist-pct">{xssPct}%</span>
              </div>
              <div className="dist-bar-bg">
                <div className="dist-bar-fill bg-tertiary" style={{width: `${Math.max(xssPct, 5)}%`}}></div>
              </div>
            </div>

            <div className="dist-item">
              <div className="dist-row">
                <span className="dist-name">IDOR / Boundary</span>
                <span className="dist-pct">{idorPct}%</span>
              </div>
              <div className="dist-bar-bg">
                <div className="dist-bar-fill bg-error" style={{width: `${Math.max(idorPct, 5)}%`}}></div>
              </div>
            </div>

            <div className="dist-item">
              <div className="dist-row">
                <span className="dist-name">Open Redirect / Traversal</span>
                <span className="dist-pct">{traversalPct}%</span>
              </div>
              <div className="dist-bar-bg">
                <div className="dist-bar-fill bg-secondary" style={{width: `${Math.max(traversalPct, 5)}%`}}></div>
              </div>
            </div>

            <div className="dist-item">
              <div className="dist-row">
                <span className="dist-name">Input Validation / Type</span>
                <span className="dist-pct">{otherPct}%</span>
              </div>
              <div className="dist-bar-bg">
                <div className="dist-bar-fill bg-outline-variant" style={{width: `${Math.max(otherPct, 5)}%`}}></div>
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
            Live Fuzzing Execution Stream {activeScanId ? `(#${activeScanId.slice(0, 8)})` : ''}
          </div>
          <div className="stream-status">
            <span className="status-dot-active"></span>
            <span className="stream-status-text">Database Backed</span>
          </div>
        </div>
        
        <div className="stream-body" ref={streamRef}>
          {fuzzResults.length === 0 ? (
            <div style={{padding: '32px', textAlign: 'center', color: 'var(--color-on-surface-variant)'}}>
              No fuzzing execution records for this scan yet. Start or resume a scan to begin injecting adaptive test probes.
            </div>
          ) : (
            fuzzResults.map((item, idx) => {
              const timeStr = item.executed_at ? new Date(item.executed_at).toISOString().split('T')[1].substring(0, 12) : '00:00:00.000';
              return (
                <div key={item.id || idx} className={`stream-row ${item.anomaly_detected ? 'err-row' : ''}`}>
                  <span className="stream-time">[{timeStr}]</span>
                  <span className="stream-req">{item.category}</span>
                  <span className={`stream-code ${getCodeClass(item.status_code)}`}>{item.status_code || 200}</span>
                  <span className="stream-payload">
                    payload: <span className="payload-val">{item.payload}</span> {item.parameter_name ? `(param: ${item.parameter_name})` : ''}
                  </span>
                  {item.anomaly_detected ? (
                    <span className="stream-anomaly">
                      <span className="material-symbols-outlined" style={{fontSize: '14px'}}>bug_report</span> ANOMALY DETECTED
                    </span>
                  ) : (
                    <span style={{width: '128px', fontSize: '11px', color: 'var(--color-on-surface-variant)', textAlign: 'right'}}>
                      {item.response_time_ms ? `${item.response_time_ms.toFixed(0)}ms` : ''}
                    </span>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>

    </div>
  );
}
