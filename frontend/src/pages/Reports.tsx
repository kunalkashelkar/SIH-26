import React, { useState, useEffect } from 'react';
import { scanService, ScanListItem } from '../services/api';
import './Reports.css';

export default function Reports() {
  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [filterText, setFilterText] = useState<string>('');
  const [downloading, setDownloading] = useState<string | null>(null);

  useEffect(() => {
    async function loadReports() {
      try {
        setLoading(true);
        const data = await scanService.getScans(50);
        setScans(data);
      } catch (e) {
        console.warn("Reports scans fetch error:", e);
      } finally {
        setLoading(false);
      }
    }
    loadReports();
  }, []);

  const handleDownloadPdf = async (scanId: string) => {
    try {
      setDownloading(`pdf-${scanId}`);
      const url = scanService.downloadPdfReportUrl(scanId);
      const res = await fetch(url);
      if (!res.ok) throw new Error("Failed to download PDF report");
      const blob = await res.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = `security_report_${scanId.slice(0, 8)}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (err: any) {
      alert(`PDF download failed: ${err.message || err}`);
    } finally {
      setDownloading(null);
    }
  };

  const handleDownloadJson = async (scanId: string) => {
    try {
      setDownloading(`json-${scanId}`);
      const data = await scanService.getScanJsonReport(scanId);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = `security_report_${scanId.slice(0, 8)}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (err: any) {
      alert(`JSON report fetch failed: ${err.message || err}`);
    } finally {
      setDownloading(null);
    }
  };

  const handleDownloadSarif = async (scanId: string) => {
    try {
      setDownloading(`sarif-${scanId}`);
      const data = await scanService.getScanSarifReport(scanId);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = `security_report_${scanId.slice(0, 8)}.sarif`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (err: any) {
      alert(`SARIF report fetch failed: ${err.message || err}`);
    } finally {
      setDownloading(null);
    }
  };

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
        <h1 className="page-title m-0">Security Reports</h1>
        <div className="reports-actions">
          <div className="reports-search">
            <span className="material-symbols-outlined">search</span>
            <input 
              type="text" 
              className="reports-search-input" 
              placeholder="Filter reports..." 
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
            />
          </div>
          <button className="btn-icon-outline">
            <span className="material-symbols-outlined text-[20px]">filter_list</span>
          </button>
        </div>
      </div>

      <div className="reports-grid">
        {loading ? (
          <div style={{gridColumn: 'span 3', padding: '32px', textAlign: 'center', color: 'var(--color-on-surface-variant)'}}>
            Loading security reports...
          </div>
        ) : displayedScans.length === 0 ? (
          <div style={{gridColumn: 'span 3', padding: '32px', textAlign: 'center', color: 'var(--color-on-surface-variant)'}}>
            No scan reports available. Start a scan to generate comprehensive audit reports.
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
                    <div className={`report-badge ${hasFindings ? (scan.critical_findings > 0 ? 'badge-red' : 'badge-yellow') : 'badge-gray'}`}>
                      <span className="material-symbols-outlined text-[14px]">
                        {hasFindings ? 'warning' : 'check_circle'}
                      </span>
                      {scan.total_findings} Confirmed Findings
                    </div>
                  </div>
                  
                  <div className="report-divider"></div>
                  
                  <div className="report-actions">
                    <button className="btn-view" onClick={() => handleDownloadJson(scan.id)}>
                      <span className="material-symbols-outlined text-[16px]">visibility</span> View JSON
                    </button>
                    <div className="download-group">
                      <button 
                        className="btn-download" 
                        title="Download PDF" 
                        onClick={() => handleDownloadPdf(scan.id)}
                        disabled={downloading === `pdf-${scan.id}`}
                      >
                        <span className="material-symbols-outlined text-[18px]">picture_as_pdf</span>
                      </button>
                      <button 
                        className="btn-download font-mono-sm" 
                        title="Download JSON"
                        onClick={() => handleDownloadJson(scan.id)}
                        disabled={downloading === `json-${scan.id}`}
                      >
                        {'{ }'}
                      </button>
                      <button 
                        className="btn-download font-small-caps" 
                        title="Download SARIF"
                        onClick={() => handleDownloadSarif(scan.id)}
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
