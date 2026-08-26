import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { targetService, scanService, TargetItem } from '../services/api';
import './Targets.css';

export default function Targets() {
  const navigate = useNavigate();
  const [targets, setTargets] = useState<TargetItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [filterText, setFilterText] = useState<string>('');
  const [showAddModal, setShowAddModal] = useState<boolean>(false);
  const [newUrl, setNewUrl] = useState<string>('');
  const [newName, setNewName] = useState<string>('');
  const [newDesc, setNewDesc] = useState<string>('');
  const [submitting, setSubmitting] = useState<boolean>(false);

  const loadTargets = async () => {
    try {
      setLoading(true);
      const data = await targetService.getTargets();
      setTargets(data);
    } catch (e) {
      console.warn("Targets fetch error:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTargets();
  }, []);

  const handleAddTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUrl) return;
    try {
      setSubmitting(true);
      await targetService.createTarget({
        base_url: newUrl,
        name: newName || undefined,
        description: newDesc || undefined
      });
      setNewUrl('');
      setNewName('');
      setNewDesc('');
      setShowAddModal(false);
      await loadTargets();
    } catch (err: any) {
      alert(`Failed to add target: ${err.message || err}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleStartScan = async (target: TargetItem) => {
    try {
      const res = await scanService.createScan({
        target_url: target.base_url,
        target_id: target.id,
        scan_mode: 'Standard',
        max_depth: 3,
        max_requests: 5000
      });
      localStorage.setItem('last_active_scan_id', res.scan_id);
      navigate(`/scans/${res.scan_id}/progress`);
    } catch (err: any) {
      alert(`Failed to start scan: ${err.message || err}`);
    }
  };

  const handleDeleteTarget = async (targetId: string) => {
    if (!window.confirm("Are you sure you want to delete this target?")) return;
    try {
      await targetService.deleteTarget(targetId);
      await loadTargets();
    } catch (err: any) {
      alert(`Failed to delete target: ${err.message || err}`);
    }
  };

  const displayedTargets = targets.filter(t => 
    !filterText || 
    t.base_url.toLowerCase().includes(filterText.toLowerCase()) ||
    t.name.toLowerCase().includes(filterText.toLowerCase()) ||
    (t.description || '').toLowerCase().includes(filterText.toLowerCase())
  );

  const getRiskBadge = (risk: string) => {
    const r = (risk || 'LOW').toUpperCase();
    if (r === 'CRITICAL') {
      return (
        <span className="status-badge-inline critical">
          <span className="material-symbols-outlined text-[14px]">warning</span> Critical
        </span>
      );
    }
    if (r === 'HIGH') {
      return (
        <span className="status-badge-inline high">
          <span className="material-symbols-outlined text-[14px]">error</span> High
        </span>
      );
    }
    if (r === 'MEDIUM') {
      return (
        <span className="status-badge-inline medium">
          <span className="material-symbols-outlined text-[14px]">info</span> Medium
        </span>
      );
    }
    return (
      <span className="status-badge-inline low">
        <span className="material-symbols-outlined text-[14px]">check_circle</span> Low
      </span>
    );
  };

  const formatLastScanned = (dateStr?: string | null) => {
    if (!dateStr) return 'Never';
    const d = new Date(dateStr);
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  };

  return (
    <div className="page-container">
      <div className="targets-header">
        <div className="targets-title-group">
          <h1 className="page-title m-0 mb-1">Target Inventory</h1>
          <p className="page-subtitle m-0">Manage and monitor your defined scanning targets and their associated risk profiles.</p>
        </div>
        <button className="btn-primary font-caps shadow-sm" onClick={() => setShowAddModal(true)}>
          <span className="material-symbols-outlined text-[18px] mr-2">add</span>
          Add Target
        </button>
      </div>

      {showAddModal && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.7)', zIndex: 1000,
          display: 'flex', alignItems: 'center', justifyContent: 'center'
        }}>
          <div className="card" style={{maxWidth: '480px', width: '100%', padding: '24px', background: 'var(--color-surface)', borderRadius: '12px'}}>
            <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px'}}>
              <h2 style={{margin: 0, fontSize: '18px', fontWeight: 700}}>Add New Target</h2>
              <button className="btn-icon-transparent" onClick={() => setShowAddModal(false)}>
                <span className="material-symbols-outlined">close</span>
              </button>
            </div>
            <form onSubmit={handleAddTarget}>
              <div style={{marginBottom: '16px'}}>
                <label className="form-label">Target URL *</label>
                <input 
                  type="url" 
                  className="form-input" 
                  placeholder="https://example.com" 
                  value={newUrl}
                  onChange={(e) => setNewUrl(e.target.value)}
                  required 
                />
              </div>
              <div style={{marginBottom: '16px'}}>
                <label className="form-label">Target Name</label>
                <input 
                  type="text" 
                  className="form-input" 
                  placeholder="Production Web App" 
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                />
              </div>
              <div style={{marginBottom: '20px'}}>
                <label className="form-label">Description</label>
                <textarea 
                  className="form-input" 
                  rows={3}
                  placeholder="Scope details and environment notes..."
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                />
              </div>
              <div style={{display: 'flex', justifyContent: 'flex-end', gap: '12px'}}>
                <button type="button" className="btn-link" onClick={() => setShowAddModal(false)}>Cancel</button>
                <button type="submit" className="btn-primary" disabled={submitting}>
                  {submitting ? 'Adding...' : 'Save Target'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <div className="targets-table-container">
        <div className="targets-toolbar">
          <div className="targets-search">
            <span className="material-symbols-outlined">filter_list</span>
            <input 
              type="text" 
              className="targets-search-input" 
              placeholder="Filter targets..." 
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
            />
          </div>
          <div className="flex items-center gap-4">
            <span className="font-body-sm text-muted">Showing {displayedTargets.length} targets</span>
          </div>
        </div>

        <table className="targets-table">
          <thead>
            <tr>
              <th>Target URL</th>
              <th>Last Scanned</th>
              <th className="text-right">Total Findings</th>
              <th>Risk Status</th>
              <th className="text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={5} style={{textAlign: 'center', padding: '32px', color: 'var(--color-on-surface-variant)'}}>
                  Loading target inventory...
                </td>
              </tr>
            ) : displayedTargets.length === 0 ? (
              <tr>
                <td colSpan={5} style={{textAlign: 'center', padding: '32px', color: 'var(--color-on-surface-variant)'}}>
                  No targets configured yet. Click "Add Target" to register your first target domain.
                </td>
              </tr>
            ) : (
              displayedTargets.map((target, idx) => (
                <tr key={target.id} className={idx % 2 === 1 ? "stripe" : ""}>
                  <td className="font-mono-sm text-primary">
                    <div>{target.base_url}</div>
                    {target.name && target.name !== target.base_url && (
                      <div className="text-muted" style={{fontSize: '11px'}}>{target.name}</div>
                    )}
                  </td>
                  <td className="font-body-sm text-muted">{formatLastScanned(target.last_scanned)}</td>
                  <td className="font-mono-md text-right">{target.total_findings}</td>
                  <td>{getRiskBadge(target.risk_status)}</td>
                  <td className="text-right">
                    <button className="table-action-btn primary" onClick={() => handleStartScan(target)}>Scan</button>
                    <button className="table-action-btn error" onClick={() => handleDeleteTarget(target.id)}>Delete</button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
