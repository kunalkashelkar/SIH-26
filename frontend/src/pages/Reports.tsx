import React from 'react';
import './Reports.css';

export default function Reports() {
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
            />
          </div>
          <button className="btn-icon-outline">
            <span className="material-symbols-outlined text-[20px]">filter_list</span>
          </button>
          <button className="btn-primary flex items-center gap-2 font-caps shadow-sm" style={{padding: '8px 16px', borderRadius: '6px'}}>
            <span className="material-symbols-outlined text-[18px]">add</span>
            Generate New Report
          </button>
        </div>
      </div>

      <div className="reports-grid">
        {/* Report Card 1 */}
        <div className="report-card group">
          <div className="report-card-glow glow-primary"></div>
          <div className="report-card-content">
            <div className="report-header">
              <div className="flex items-center gap-3">
                <div className="report-icon-box primary">
                  <span className="material-symbols-outlined">description</span>
                </div>
                <div>
                  <h3 className="report-title">example.com</h3>
                  <p className="report-date">Aug 17, 2026</p>
                </div>
              </div>
              <div className="report-badge badge-red">
                <span className="material-symbols-outlined text-[14px]">warning</span>
                23 Findings
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
