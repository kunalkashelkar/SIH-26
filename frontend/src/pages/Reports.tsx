import React, { useState, useEffect } from 'react';
import { scanService } from '../services/api';
import './Reports.css';

export default function Reports() {
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [filterText, setFilterText] = useState<string>('');
  const [downloading, setDownloading] = useState<string | null>(null);

  const activeScanId = localStorage.getItem('last_active_scan_id');

  useEffect(() => {
    async function loadReports() {
      if (activeScanId) {
        try {
          setLoading(true);
          const data = await scanService.getScanStatistics(activeScanId);
          setStats(data);
        } catch (e) {
          console.warn("Reports stats fetch:", e);
        } finally {
          setLoading(false);
        }
      } else {
        setLoading(false);
      }
    }
    loadReports();
  }, [activeScanId]);

  const handleDownloadPdf = async (scanId: string) => {
    try {
      setDownloading(scanId);
      const url = scanService.downloadPdfReportUrl(scanId);
      const res = await fetch(url);
      if (!res.ok) throw new Error("Failed to download PDF report");
      const blob = await res.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = `security_report_${scanId}.pdf`;
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
      const data = await scanService.getScanJsonReport(scanId);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = `security_report_${scanId}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (err: any) {
      alert(`JSON report fetch failed: ${err.message || err}`);
    }
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
        {/* Real Scan Report Card */}
        {stats && (
          <div className="report-card group">
            <div className="report-card-glow glow-primary"></div>
            <div className="report-card-content">
              <div className="report-header">
                <div className="flex items-center gap-3">
                  <div className="report-icon-box primary">
                    <span className="material-symbols-outlined">description</span>
                  </div>
                  <div>
                    <h3 className="report-title">{stats.target_url}</h3>
                    <p className="report-date">Scan: {stats.scan_id.slice(0, 8)}... | Status: {stats.status}</p>
                  </div>
                </div>
                <div className={`report-badge ${stats.total_findings > 0 ? 'badge-red' : 'badge-gray'}`}>
                  <span className="material-symbols-outlined text-[14px]">
                    {stats.total_findings > 0 ? 'warning' : 'check_circle'}
                  </span>
                  {stats.total_findings} Confirmed Findings
                </div>
              </div>
              
              <div className="report-divider"></div>
              
              <div className="report-actions">
                <button className="btn-view" onClick={() => handleDownloadJson(stats.scan_id)}>
                  <span className="material-symbols-outlined text-[16px]">visibility</span> View JSON
                </button>
                <div className="download-group">
                  <button 
                    className="btn-download" 
                    title="Download PDF" 
                    onClick={() => handleDownloadPdf(stats.scan_id)}
                    disabled={downloading === stats.scan_id}
                  >
                    <span className="material-symbols-outlined text-[18px]">picture_as_pdf</span>
                  </button>
                  <button 
                    className="btn-download font-mono-sm" 
                    title="Download JSON"
                    onClick={() => handleDownloadJson(stats.scan_id)}
                  >
                    {'{ }'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Report Card 2 */}
        <div className="report-card group">
          <div className="report-card-glow glow-tertiary"></div>
          <div className="report-card-content">
            <div className="report-header">
              <div className="flex items-center gap-3">
                <div className="report-icon-box tertiary">
                  <span className="material-symbols-outlined">description</span>
                </div>
                <div>
                  <h3 className="report-title">api.acme.corp</h3>
                  <p className="report-date">Aug 12, 2026</p>
                </div>
              </div>
              <div className="report-badge badge-yellow">
                <span className="material-symbols-outlined text-[14px]">warning</span>
                8 Findings
              </div>
            </div>
            
            <div className="report-divider"></div>
            
            <div className="report-actions">
              <button className="btn-view">
                <span className="material-symbols-outlined text-[16px]">visibility</span> View
              </button>
              <div className="download-group">
                <button className="btn-download" title="Download PDF">
                  <span className="material-symbols-outlined text-[18px]">picture_as_pdf</span>
                </button>
                <button className="btn-download font-mono-sm" title="Download JSON">
                  {'{ }'}
                </button>
                <button className="btn-download font-small-caps" title="Download SARIF">
                  SARIF
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Report Card 3 */}
        <div className="report-card group">
          <div className="report-card-glow glow-primary"></div>
          <div className="report-card-content">
            <div className="report-header">
              <div className="flex items-center gap-3">
                <div className="report-icon-box primary">
                  <span className="material-symbols-outlined">description</span>
                </div>
                <div>
                  <h3 className="report-title">staging.dev.io</h3>
                  <p className="report-date">Aug 05, 2026</p>
                </div>
              </div>
              <div className="report-badge badge-gray">
                <span className="material-symbols-outlined text-[14px]">check_circle</span>
                0 Findings
              </div>
            </div>
            
            <div className="report-divider"></div>
            
            <div className="report-actions">
              <button className="btn-view">
                <span className="material-symbols-outlined text-[16px]">visibility</span> View
              </button>
              <div className="download-group">
                <button className="btn-download" title="Download PDF">
                  <span className="material-symbols-outlined text-[18px]">picture_as_pdf</span>
                </button>
                <button className="btn-download font-mono-sm" title="Download JSON">
                  {'{ }'}
                </button>
                <button className="btn-download font-small-caps" title="Download SARIF">
                  SARIF
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
