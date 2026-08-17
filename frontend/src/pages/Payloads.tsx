import React from 'react';
import './Payloads.css';

export default function Payloads() {
  return (
    <div className="payloads-container">
      {/* Decorative Ambient Background */}
      <div className="payloads-bg-decor">
        <svg preserveAspectRatio="none" viewBox="0 0 1000 400">
          <defs>
            <linearGradient id="fadeG" x1="0" x2="1" y1="0" y2="0">
              <stop offset="0%" stopColor="transparent"></stop>
              <stop offset="100%" stopColor="currentColor"></stop>
            </linearGradient>
          </defs>
          <path d="M0,200 Q250,50 500,200 T1000,200 L1000,0 L0,0 Z" fill="url(#fadeG)" style={{animationDuration: '8s'}}></path>
          <path d="M0,300 Q250,150 500,300 T1000,300 L1000,0 L0,0 Z" fill="url(#fadeG)" style={{animationDuration: '12s', opacity: 0.5}}></path>
        </svg>
      </div>

      {/* Header Section */}
      <div className="payloads-header">
        <div className="payloads-title-group">
          <div className="payloads-label font-caps">
            <span className="material-symbols-outlined text-[18px]">bolt</span>
            <span>Attack Surface Library</span>
          </div>
          <h1 className="page-title m-0">Payloads Management</h1>
          <p className="page-subtitle max-w-2xl mt-1" style={{maxWidth: '42rem'}}>
            Curate, monitor, and deploy custom fuzzing payloads. Analyze success rates across recent scan cycles to optimize mutation engines.
          </p>
        </div>
        <button className="btn-primary shadow-sm" style={{padding: '12px 24px', fontSize: '16px'}}>
          <span className="material-symbols-outlined text-[20px]">add</span>
          Add Payload
        </button>
      </div>

      {/* Metrics Bento Grid */}
      <div className="payloads-bento-grid">
        {/* Total Payloads */}
        <div className="bento-card bento-card-small">
          <div className="bento-glow-primary"></div>
          <div className="bento-header">
            <span className="font-caps text-muted">Total Payloads</span>
            <span className="material-symbols-outlined text-primary text-[24px]">database</span>
          </div>
          <div className="bento-value-row">
            <span className="bento-value-xl">4,892</span>
            <span className="font-mono-sm text-secondary" style={{backgroundColor: '#32353b', padding: '2px 8px', borderRadius: '4px'}}>+124 this week</span>
          </div>
        </div>

        {/* Highest Success Rate */}
        <div className="bento-card bento-card-small">
          <div className="bento-glow-tertiary"></div>
          <div className="bento-header">
            <span className="font-caps text-muted">Top Vector</span>
            <span className="material-symbols-outlined text-tertiary text-[24px]">crisis_alert</span>
          </div>
          <div className="bento-value-row">
            <span className="bento-value-lg text-tertiary">OS Command</span>
            <span className="font-mono-sm text-muted">28.4% success</span>
          </div>
        </div>

        {/* Activity Sparkline */}
        <div className="bento-card bento-card-large">
          <div className="bento-header" style={{marginBottom: '8px'}}>
            <span className="font-caps text-muted">Usage Frequency (30d)</span>
            <div className="flex gap-1">
              <span className="pill-dot bg-primary"></span>
              <span className="pill-dot" style={{backgroundColor: '#32353b'}}></span>
              <span className="pill-dot" style={{backgroundColor: '#32353b'}}></span>
            </div>
          </div>
          <div className="flex-1 w-full h-16 relative flex items-end">
            <svg className="w-full h-full" style={{overflow: 'visible'}} preserveAspectRatio="none" viewBox="0 0 400 60">
              <path className="text-primary" d="M0,50 C20,40 40,60 60,30 C80,0 100,20 120,40 C140,60 160,20 180,10 C200,0 220,30 240,40 C260,50 280,10 300,20 C320,30 340,50 360,20 C380,-10 400,20 400,20" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"></path>
              <path className="text-primary" style={{opacity: 0.1}} d="M0,50 C20,40 40,60 60,30 C80,0 100,20 120,40 C140,60 160,20 180,10 C200,0 220,30 240,40 C260,50 280,10 300,20 C320,30 340,50 360,20 C380,-10 400,20 400,20 L400,60 L0,60 Z" fill="currentColor"></path>
            </svg>
          </div>
        </div>
      </div>

      <div className="flex flex-col gap-6 relative z-10">
        {/* Filters & Search */}
        <div className="payloads-filters">
          <div className="filter-pills">
            <button className="filter-pill active">All Vectors</button>
            <button className="filter-pill">
              <span className="pill-dot bg-primary"></span> SQLi
            </button>
            <button className="filter-pill">
              <span className="pill-dot text-tertiary" style={{backgroundColor: 'currentColor'}}></span> XSS
            </button>
            <button className="filter-pill">
              <span className="pill-dot text-secondary" style={{backgroundColor: 'currentColor'}}></span> Path Traversal
            </button>
            <button className="filter-pill">
              <span className="pill-dot text-error" style={{backgroundColor: 'currentColor'}}></span> OS Command
            </button>
          </div>
          <div className="reports-search" style={{maxWidth: '320px', width: '100%'}}>
            <span className="material-symbols-outlined">filter_list</span>
            <input 
              type="text" 
              className="reports-search-input" 
              placeholder="Filter strings..." 
            />
          </div>
        </div>

        {/* Data Table */}
        <div className="payloads-table-container">
          <div className="payloads-table-header font-caps text-muted">
            <div style={{gridColumn: 'span 5'}}>Payload Content</div>
            <div style={{gridColumn: 'span 2'}}>Category</div>
            <div style={{gridColumn: 'span 2', textAlign: 'right'}}>Success Rate</div>
            <div style={{gridColumn: 'span 2', textAlign: 'right'}}>Usage Count</div>
            <div style={{gridColumn: 'span 1'}}></div>
          </div>

          <div className="flex flex-col">
            {/* Row 1 */}
            <div className="payloads-row">
              <div className="row-accent bg-primary"></div>
              <div style={{gridColumn: 'span 5', paddingRight: '16px', display: 'flex', alignItems: 'center'}}>
                <div className="payload-code-container">
                  <code className="text-primary">' UNION SELECT null, version(), database() --</code>
                  <button className="copy-btn">
                    <span className="material-symbols-outlined text-[14px]">content_copy</span>
                  </button>
                </div>
              </div>
              <div style={{gridColumn: 'span 2', display: 'flex', alignItems: 'center'}}>
                <span className="category-badge text-primary" style={{backgroundColor: 'rgba(88, 166, 255, 0.1)'}}>
                  <span className="pill-dot bg-primary mr-2" style={{marginRight: '8px', width: '6px', height: '6px'}}></span>SQLi
                </span>
              </div>
              <div style={{gridColumn: 'span 2', display: 'flex', flexDirection: 'column', gap: '6px', justifyContent: 'center'}}>
                <div className="font-mono-sm text-primary">24.8%</div>
                <div className="progress-bar-container">
                  <div className="progress-bar-fill bg-primary" style={{width: '24.8%'}}></div>
                </div>
              </div>
              <div className="font-mono-sm text-muted" style={{gridColumn: 'span 2', textAlign: 'right', display: 'flex', alignItems: 'center', justifyContent: 'flex-end'}}>
                14,290
              </div>
              <div className="row-actions" style={{gridColumn: 'span 1'}}>
                <button className="action-btn"><span className="material-symbols-outlined text-[18px]">edit</span></button>
                <button className="action-btn delete"><span className="material-symbols-outlined text-[18px]">delete</span></button>
              </div>
            </div>

            {/* Row 2 */}
            <div className="payloads-row stripe">
              <div className="row-accent text-tertiary" style={{backgroundColor: 'currentColor'}}></div>
              <div style={{gridColumn: 'span 5', paddingRight: '16px', display: 'flex', alignItems: 'center'}}>
                <div className="payload-code-container">
                  <code className="text-tertiary">{`"><svg/onload=prompt(1)>`}</code>
                  <button className="copy-btn">
                    <span className="material-symbols-outlined text-[14px]">content_copy</span>
                  </button>
                </div>
              </div>
              <div style={{gridColumn: 'span 2', display: 'flex', alignItems: 'center'}}>
                <span className="category-badge text-tertiary" style={{backgroundColor: 'rgba(255, 186, 66, 0.1)'}}>
                  <span className="pill-dot bg-tertiary mr-2" style={{marginRight: '8px', width: '6px', height: '6px'}}></span>XSS
                </span>
              </div>
              <div style={{gridColumn: 'span 2', display: 'flex', flexDirection: 'column', gap: '6px', justifyContent: 'center'}}>
                <div className="font-mono-sm text-tertiary">18.2%</div>
                <div className="progress-bar-container">
                  <div className="progress-bar-fill bg-tertiary" style={{width: '18.2%'}}></div>
                </div>
              </div>
              <div className="font-mono-sm text-muted" style={{gridColumn: 'span 2', textAlign: 'right', display: 'flex', alignItems: 'center', justifyContent: 'flex-end'}}>
                8,441
              </div>
              <div className="row-actions" style={{gridColumn: 'span 1'}}>
                <button className="action-btn"><span className="material-symbols-outlined text-[18px]">edit</span></button>
                <button className="action-btn delete"><span className="material-symbols-outlined text-[18px]">delete</span></button>
              </div>
            </div>

            {/* Row 3 */}
            <div className="payloads-row">
              <div className="row-accent text-secondary" style={{backgroundColor: 'currentColor'}}></div>
              <div style={{gridColumn: 'span 5', paddingRight: '16px', display: 'flex', alignItems: 'center'}}>
                <div className="payload-code-container">
                  <code className="text-secondary">../../../../../../etc/passwd%00</code>
                  <button className="copy-btn">
                    <span className="material-symbols-outlined text-[14px]">content_copy</span>
                  </button>
                </div>
              </div>
              <div style={{gridColumn: 'span 2', display: 'flex', alignItems: 'center'}}>
                <span className="category-badge text-secondary" style={{backgroundColor: 'rgba(193, 199, 208, 0.1)'}}>
                  <span className="pill-dot bg-secondary mr-2" style={{marginRight: '8px', width: '6px', height: '6px'}}></span>Traversal
                </span>
              </div>
              <div style={{gridColumn: 'span 2', display: 'flex', flexDirection: 'column', gap: '6px', justifyContent: 'center'}}>
                <div className="font-mono-sm text-secondary">8.9%</div>
                <div className="progress-bar-container">
                  <div className="progress-bar-fill bg-secondary" style={{width: '8.9%'}}></div>
                </div>
              </div>
              <div className="font-mono-sm text-muted" style={{gridColumn: 'span 2', textAlign: 'right', display: 'flex', alignItems: 'center', justifyContent: 'flex-end'}}>
                5,112
              </div>
              <div className="row-actions" style={{gridColumn: 'span 1'}}>
                <button className="action-btn"><span className="material-symbols-outlined text-[18px]">edit</span></button>
                <button className="action-btn delete"><span className="material-symbols-outlined text-[18px]">delete</span></button>
              </div>
            </div>

            {/* Row 4 */}
            <div className="payloads-row stripe">
              <div className="row-accent text-error" style={{backgroundColor: 'currentColor'}}></div>
              <div style={{gridColumn: 'span 5', paddingRight: '16px', display: 'flex', alignItems: 'center'}}>
                <div className="payload-code-container">
                  <code className="text-error">127.0.0.1; ping -c 3 127.0.0.1</code>
                  <button className="copy-btn">
                    <span className="material-symbols-outlined text-[14px]">content_copy</span>
                  </button>
                </div>
              </div>
              <div style={{gridColumn: 'span 2', display: 'flex', alignItems: 'center'}}>
                <span className="category-badge text-error" style={{backgroundColor: 'rgba(255, 180, 171, 0.1)'}}>
                  <span className="pill-dot bg-error mr-2" style={{marginRight: '8px', width: '6px', height: '6px'}}></span>OS Cmd
                </span>
              </div>
              <div style={{gridColumn: 'span 2', display: 'flex', flexDirection: 'column', gap: '6px', justifyContent: 'center'}}>
                <div className="font-mono-sm text-error">28.4%</div>
                <div className="progress-bar-container">
                  <div className="progress-bar-fill bg-error" style={{width: '28.4%'}}></div>
                </div>
              </div>
              <div className="font-mono-sm text-muted" style={{gridColumn: 'span 2', textAlign: 'right', display: 'flex', alignItems: 'center', justifyContent: 'flex-end'}}>
                2,904
              </div>
              <div className="row-actions" style={{gridColumn: 'span 1'}}>
                <button className="action-btn"><span className="material-symbols-outlined text-[18px]">edit</span></button>
                <button className="action-btn delete"><span className="material-symbols-outlined text-[18px]">delete</span></button>
              </div>
            </div>
          </div>

          <div className="table-footer">
            <span className="font-body text-muted" style={{fontSize: '12px'}}>Showing 1 to 4 of 4,892 entries</span>
            <div className="pagination">
              <button className="page-btn icon-btn" disabled><span className="material-symbols-outlined text-[20px]">chevron_left</span></button>
              <button className="page-btn active">1</button>
              <button className="page-btn">2</button>
              <button className="page-btn">3</button>
              <span className="text-muted" style={{padding: '0 8px'}}>...</span>
              <button className="page-btn icon-btn"><span className="material-symbols-outlined text-[20px]">chevron_right</span></button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
