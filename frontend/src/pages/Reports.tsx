import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { scanService, ScanListItem } from '../services/api';
import './Reports.css';

export default function Reports() {
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [filterText, setFilterText] = useState<string>('');
  const [downloading, setDownloading] = useState<string | null>(null);

  const loadReports = async () => {
    try {
      setLoading(true);
      const data = await scanService.getScans(50);
      setScans(data);
    } catch (e) {
      console.warn("Reports scans fetch error:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadReports();
  }, []);

  const handleDownloadPdf = async (scan: ScanListItem) => {
    try {
      setDownloading(`pdf-${scan.id}`);
      const url = scanService.downloadPdfReportUrl(scan.id);
      const res = await fetch(url);
      if (!res.ok) throw new Error("Failed to download PDF report");
      const blob = await res.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      
      // Clean, consistent file naming: security_report_<target_host>_<scan_id_short>.pdf
      const safeTarget = scan.target_url.replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9_-]/g, '_');
      a.download = `security_report_${safeTarget}_${scan.id.slice(0, 8)}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (err: any) {
      alert(`PDF download failed: ${err.message || err}`);
    } finally {
      setDownloading(null);
    }
  };

  const handleDownloadJson = async (scan: ScanListItem) => {
    try {
      setDownloading(`json-${scan.id}`);
      const data = await scanService.getScanJsonReport(scan.id);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      
      const safeTarget = scan.target_url.replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9_-]/g, '_');
      a.download = `security_report_${safeTarget}_${scan.id.slice(0, 8)}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (err: any) {
      alert(`JSON report fetch failed: ${err.message || err}`);
    } finally {
      setDownloading(null);
    }
  };

  const handleDownloadSarif = async (scan: ScanListItem) => {
    try {
      setDownloading(`sarif-${scan.id}`);
      const data = await scanService.getScanSarifReport(scan.id);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      
      const safeTarget = scan.target_url.replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9_-]/g, '_');
      a.download = `security_report_${safeTarget}_${scan.id.slice(0, 8)}.sarif`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (err: any) {
      alert(`SARIF report fetch failed: ${err.message || err}`);
    } finally {
      setDownloading(null);
    }
  };

  // Delete & Discard unwanted scan reports
  const handleDeleteReport = async (scanId: string, targetUrl: string) => {
    if (!window.confirm(`Discard report and scan data for ${targetUrl}?`)) return;
    try {
      await scanService.deleteScan(scanId);
      await loadReports();
    } catch (err: any) {
      alert(`Failed to delete report: ${err.message || err}`);
    }
  };

  const [selectedScanForPreview, setSelectedScanForPreview] = useState<ScanListItem | null>(null);

  const displayedScans = scans.filter(s => 
    !filterText || 
    s.target_url.toLowerCase().includes(filterText.toLowerCase()) ||
    s.status.toLowerCase().includes(filterText.toLowerCase()) ||
    s.id.toLowerCase().includes(filterText.toLowerCase())
  );

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'Recently';
    const d = new Date(dateStr);
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  };

  return (
    <div className="page-container">
      <div className="reports-header">
        <div style={{display: 'flex', alignItems: 'center', gap: '16px'}}>
          <button className="btn-back" onClick={() => navigate(-1)} title="Go Back">
            <span className="material-symbols-outlined">arrow_back</span>
          </button>
          <div>
            <h1 className="page-title m-0">Security Audit Reports</h1>
            <p className="page-subtitle m-0 mt-1">Export Executive PDFs, Technical SARIF findings, or raw JSON assessments.</p>
          </div>
        </div>

        <div className="reports-actions">
          <div className="reports-search">
            <span className="material-symbols-outlined">search</span>
            <input 
              type="text" 
              className="reports-search-input" 
              placeholder="Filter by target or ID..." 
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
            />
          </div>
        </div>
      </div>

      {/* Format Legend / Guide */}
      <div style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: '12px',
        alignItems: 'center',
        padding: '12px 16px',
        background: 'var(--color-surface)',
        borderRadius: '6px',
        border: '1px solid var(--color-outline-variant)',
        fontSize: '12px'
      }}>
        <span style={{fontWeight: 700, color: 'var(--color-on-surface)'}}>Report Formats:</span>
        <span style={{display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--color-primary)'}}>
          <span className="material-symbols-outlined" style={{fontSize: '16px'}}>picture_as_pdf</span> Executive PDF (Board & CISO)
        </span>
        <span style={{color: 'var(--color-outline-variant)'}}>•</span>
        <span style={{display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--color-tertiary)'}}>
          <span className="material-symbols-outlined" style={{fontSize: '16px'}}>terminal</span> Technical SARIF (CI/CD & GitHub Security)
        </span>
        <span style={{color: 'var(--color-outline-variant)'}}>•</span>
        <span style={{display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--color-secondary)'}}>
          <span className="material-symbols-outlined" style={{fontSize: '16px'}}>code</span> JSON Export (SIEM & Data Lake)
        </span>
      </div>

      <div className="reports-grid">
        {loading ? (
          <div style={{gridColumn: 'span 3', padding: '32px', textAlign: 'center', color: 'var(--color-on-surface-variant)'}}>
            Loading security reports...
          </div>
        ) : displayedScans.length === 0 ? (
          <div style={{gridColumn: 'span 3', padding: '32px', textAlign: 'center', color: 'var(--color-on-surface-variant)'}}>
            No scan reports found. Run a target scan to generate auditable compliance reports.
          </div>
        ) : (
          displayedScans.map((scan) => {
            const hasFindings = scan.total_findings > 0;
            const glowClass = scan.critical_findings > 0 ? 'glow-error' : scan.high_findings > 0 ? 'glow-tertiary' : 'glow-primary';
            const iconBoxClass = scan.critical_findings > 0 ? 'error' : scan.high_findings > 0 ? 'tertiary' : 'primary';

            return (
              <div key={scan.id} className="report-card group">
                <div className={`report-card-glow ${glowClass}`}></div>
                <div className="report-card-content">
                  <div className="report-header">
                    <div className="flex items-center gap-3">
                      <div className={`report-icon-box ${iconBoxClass}`}>
                        <span className="material-symbols-outlined">description</span>
                      </div>
                      <div>
                        <h3 className="report-title">{scan.target_url}</h3>
                        <p className="report-date">
                          Scan #{scan.id.slice(0, 8)} • {formatDate(scan.started_at)}
                        </p>
                      </div>
                    </div>
                    
                    <div style={{display: 'flex', alignItems: 'center', gap: '8px'}}>
                      <div className={`report-badge ${hasFindings ? (scan.critical_findings > 0 ? 'badge-red' : 'badge-yellow') : 'badge-gray'}`}>
                        <span className="material-symbols-outlined text-[14px]">
                          {hasFindings ? 'warning' : 'check_circle'}
                        </span>
                        {scan.total_findings} Findings
                      </div>
                      <button 
                        className="btn-icon-transparent"
                        onClick={() => handleDeleteReport(scan.id, scan.target_url)}
                        title="Discard this report and scan history"
                        style={{color: 'var(--color-error)'}}
                      >
                        <span className="material-symbols-outlined text-[18px]">delete</span>
                      </button>
                    </div>
                  </div>
                  
                  <div className="report-divider"></div>
                  
                  <div className="report-actions">
                    <button className="btn-view" onClick={() => navigate(`/scans/${scan.id}/findings`)}>
                      <span className="material-symbols-outlined text-[16px]">visibility</span> View Findings
                    </button>
                    <div className="download-group">
                      <button 
                        className="btn-download" 
                        title="Download PDF Report" 
                        onClick={() => handleDownloadPdf(scan)}
                        disabled={downloading === `pdf-${scan.id}`}
                      >
                        <span className="material-symbols-outlined text-[18px]">picture_as_pdf</span>
                      </button>
                      <button 
                        className="btn-download font-mono-sm" 
                        title="Download JSON Report"
                        onClick={() => handleDownloadJson(scan)}
                        disabled={downloading === `json-${scan.id}`}
                      >
                        {'{ }'}
                      </button>
                      <button 
                        className="btn-download font-small-caps" 
                        title="Download SARIF File"
                        onClick={() => handleDownloadSarif(scan)}
                        disabled={downloading === `sarif-${scan.id}`}
                      >
                        SARIF
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
