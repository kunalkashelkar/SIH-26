import React, { useState, useEffect } from 'react';
import { payloadService, PayloadItem } from '../services/api';
import './Payloads.css';

export default function Payloads() {
  const [payloads, setPayloads] = useState<PayloadItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [showAddModal, setShowAddModal] = useState<boolean>(false);
  const [newCat, setNewCat] = useState<string>('SQLI');
  const [newPayload, setNewPayload] = useState<string>('');
  const [newIndicator, setNewIndicator] = useState<string>('');
  const [newDesc, setNewDesc] = useState<string>('');
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const loadPayloads = async () => {
    try {
      setLoading(true);
      const data = await payloadService.getPayloads();
      setPayloads(data);
    } catch (e) {
      console.warn("Failed to load payloads:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPayloads();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPayload) return;
    try {
      setSubmitting(true);
      await payloadService.createPayload({
        category: newCat,
        payload: newPayload,
        indicator: newIndicator || undefined,
        description: newDesc || undefined
      });
      setNewPayload('');
      setNewIndicator('');
      setNewDesc('');
      setShowAddModal(false);
      await loadPayloads();
    } catch (err: any) {
      alert(`Failed to add payload: ${err.message || err}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!window.confirm("Are you sure you want to delete this payload?")) return;
    try {
      await payloadService.deletePayload(id);
      await loadPayloads();
    } catch (err: any) {
      alert(`Failed to delete payload: ${err.message || err}`);
    }
  };

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const displayedPayloads = payloads.filter(p => {
    const matchesCat = selectedCategory === 'ALL' || p.category.toUpperCase() === selectedCategory.toUpperCase();
    const matchesSearch = !searchQuery || 
      p.payload.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (p.description || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.category.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCat && matchesSearch;
  });

  // Calculate highest success vector
  const categoryStats: Record<string, { total: number; success: number }> = {};
  payloads.forEach(p => {
    if (!categoryStats[p.category]) categoryStats[p.category] = { total: 0, success: 0 };
    categoryStats[p.category].total += p.usage_count;
    categoryStats[p.category].success += p.success_count;
  });

  let topVectorName = 'SQLi';
  let topVectorRate = 0;
  Object.entries(categoryStats).forEach(([cat, stat]) => {
    const rate = stat.total > 0 ? (stat.success / stat.total) * 100 : 0;
    if (rate >= topVectorRate) {
      topVectorRate = rate;
      topVectorName = cat;
    }
  });

  const getCategoryClass = (cat: string) => {
    const c = cat.toUpperCase();
    if (c === 'SQLI') return 'text-primary';
    if (c === 'XSS') return 'text-tertiary';
    if (c === 'TRAVERSAL' || c === 'IDOR') return 'text-secondary';
    if (c === 'AUTH_BYPASS' || c === 'OS_COMMAND') return 'text-error';
    return 'text-primary';
  };

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
        <button className="btn-primary shadow-sm" style={{padding: '12px 24px', fontSize: '16px'}} onClick={() => setShowAddModal(true)}>
          <span className="material-symbols-outlined text-[20px]">add</span>
          Add Payload
        </button>
      </div>

      {showAddModal && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.7)', zIndex: 1000,
          display: 'flex', alignItems: 'center', justifyContent: 'center'
        }}>
          <div className="card" style={{maxWidth: '520px', width: '100%', padding: '24px', background: 'var(--color-surface)', borderRadius: '12px'}}>
            <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px'}}>
              <h2 style={{margin: 0, fontSize: '18px', fontWeight: 700}}>Add Custom Fuzzing Payload</h2>
              <button className="btn-icon-transparent" onClick={() => setShowAddModal(false)}>
                <span className="material-symbols-outlined">close</span>
              </button>
            </div>
            <form onSubmit={handleCreate}>
              <div style={{marginBottom: '16px'}}>
                <label className="form-label">Category</label>
                <select className="form-input" value={newCat} onChange={(e) => setNewCat(e.target.value)}>
                  <option value="SQLI">SQL Injection (SQLi)</option>
                  <option value="XSS">Cross-Site Scripting (XSS)</option>
                  <option value="IDOR">Insecure Direct Object Reference (IDOR)</option>
                  <option value="AUTH_BYPASS">Authentication Bypass</option>
                  <option value="OPEN_REDIRECT">Open Redirect</option>
                  <option value="TYPE_CONFUSION">Type Confusion</option>
                  <option value="INPUT_VALIDATION">Input Validation Probe</option>
                </select>
              </div>
              <div style={{marginBottom: '16px'}}>
                <label className="form-label">Payload String *</label>
                <textarea 
                  className="form-input font-mono" 
                  rows={3} 
                  placeholder="' OR '1'='1" 
                  value={newPayload} 
                  onChange={(e) => setNewPayload(e.target.value)}
                  required 
                />
              </div>
              <div style={{marginBottom: '16px'}}>
                <label className="form-label">Expected Indicator</label>
                <input 
                  type="text" 
                  className="form-input" 
                  placeholder="e.g. sql_syntax_error" 
                  value={newIndicator} 
                  onChange={(e) => setNewIndicator(e.target.value)} 
                />
              </div>
              <div style={{marginBottom: '20px'}}>
                <label className="form-label">Description</label>
                <input 
                  type="text" 
                  className="form-input" 
                  placeholder="Probe description and behavior expectations..." 
                  value={newDesc} 
                  onChange={(e) => setNewDesc(e.target.value)} 
                />
              </div>
              <div style={{display: 'flex', justifyContent: 'flex-end', gap: '12px'}}>
                <button type="button" className="btn-link" onClick={() => setShowAddModal(false)}>Cancel</button>
                <button type="submit" className="btn-primary" disabled={submitting}>
                  {submitting ? 'Saving...' : 'Save Payload'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

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
            <span className="bento-value-xl">{payloads.length}</span>
            <span className="font-mono-sm text-secondary" style={{backgroundColor: '#32353b', padding: '2px 8px', borderRadius: '4px'}}>
              Curated & Active
            </span>
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
            <span className="bento-value-lg text-tertiary">{topVectorName}</span>
            <span className="font-mono-sm text-muted">{topVectorRate > 0 ? `${topVectorRate.toFixed(1)}% hit` : 'Active Engine'}</span>
          </div>
        </div>

        {/* Activity Sparkline */}
        <div className="bento-card bento-card-large">
          <div className="bento-header" style={{marginBottom: '8px'}}>
            <span className="font-caps text-muted">Usage Frequency</span>
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
            <button 
              className={`filter-pill ${selectedCategory === 'ALL' ? 'active' : ''}`}
              onClick={() => setSelectedCategory('ALL')}
            >
              All Vectors ({payloads.length})
            </button>
            <button 
              className={`filter-pill ${selectedCategory === 'SQLI' ? 'active' : ''}`}
              onClick={() => setSelectedCategory('SQLI')}
            >
              <span className="pill-dot bg-primary"></span> SQLi
            </button>
            <button 
              className={`filter-pill ${selectedCategory === 'XSS' ? 'active' : ''}`}
              onClick={() => setSelectedCategory('XSS')}
            >
              <span className="pill-dot text-tertiary" style={{backgroundColor: 'currentColor'}}></span> XSS
            </button>
            <button 
              className={`filter-pill ${selectedCategory === 'IDOR' ? 'active' : ''}`}
              onClick={() => setSelectedCategory('IDOR')}
            >
              <span className="pill-dot text-secondary" style={{backgroundColor: 'currentColor'}}></span> IDOR
            </button>
            <button 
              className={`filter-pill ${selectedCategory === 'AUTH_BYPASS' ? 'active' : ''}`}
              onClick={() => setSelectedCategory('AUTH_BYPASS')}
            >
              <span className="pill-dot text-error" style={{backgroundColor: 'currentColor'}}></span> Auth Bypass
            </button>
            <button 
              className={`filter-pill ${selectedCategory === 'INPUT_VALIDATION' ? 'active' : ''}`}
              onClick={() => setSelectedCategory('INPUT_VALIDATION')}
            >
              <span className="pill-dot text-secondary" style={{backgroundColor: 'currentColor'}}></span> Validation
            </button>
          </div>
          <div className="reports-search" style={{maxWidth: '320px', width: '100%'}}>
            <span className="material-symbols-outlined">filter_list</span>
            <input 
              type="text" 
              className="reports-search-input" 
              placeholder="Filter strings..." 
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
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
            {loading ? (
              <div style={{padding: '32px', textAlign: 'center', color: 'var(--color-on-surface-variant)'}}>
                Loading payload library...
              </div>
            ) : displayedPayloads.length === 0 ? (
              <div style={{padding: '32px', textAlign: 'center', color: 'var(--color-on-surface-variant)'}}>
                No payloads match the selected category and filter.
              </div>
            ) : (
              displayedPayloads.map((item, idx) => {
                const colorClass = getCategoryClass(item.category);
                return (
                  <div key={item.id} className={`payloads-row ${idx % 2 === 1 ? 'stripe' : ''}`}>
                    <div className={`row-accent ${colorClass}`} style={{backgroundColor: 'currentColor'}}></div>
                    <div style={{gridColumn: 'span 5', paddingRight: '16px', display: 'flex', alignItems: 'center'}}>
                      <div className="payload-code-container">
                        <code className={colorClass}>{item.payload}</code>
                        <button className="copy-btn" onClick={() => handleCopy(item.id, item.payload)} title="Copy payload">
                          <span className="material-symbols-outlined text-[14px]">
                            {copiedId === item.id ? 'check' : 'content_copy'}
                          </span>
                        </button>
                      </div>
                    </div>
                    <div style={{gridColumn: 'span 2', display: 'flex', alignItems: 'center'}}>
                      <span className={`category-badge ${colorClass}`} style={{backgroundColor: 'rgba(255, 255, 255, 0.06)'}}>
                        <span className={`pill-dot mr-2`} style={{backgroundColor: 'currentColor', marginRight: '8px', width: '6px', height: '6px'}}></span>
                        {item.category}
                      </span>
                    </div>
                    <div style={{gridColumn: 'span 2', display: 'flex', flexDirection: 'column', gap: '6px', justifyContent: 'center'}}>
                      <div className={`font-mono-sm ${colorClass}`}>{item.success_rate.toFixed(1)}%</div>
                      <div className="progress-bar-container">
                        <div className={`progress-bar-fill`} style={{backgroundColor: 'currentColor', width: `${Math.max(item.success_rate, 4)}%`}}></div>
                      </div>
                    </div>
                    <div className="font-mono-sm text-muted" style={{gridColumn: 'span 2', textAlign: 'right', display: 'flex', alignItems: 'center', justifyContent: 'flex-end'}}>
                      {item.usage_count.toLocaleString()}
                    </div>
                    <div className="row-actions" style={{gridColumn: 'span 1'}}>
                      {item.is_custom && (
                        <button className="action-btn delete" onClick={() => handleDelete(item.id)} title="Delete Payload">
                          <span className="material-symbols-outlined text-[18px]">delete</span>
                        </button>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>

          <div className="table-footer">
            <span className="font-body text-muted" style={{fontSize: '12px'}}>
              Showing {displayedPayloads.length} of {payloads.length} entries
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
