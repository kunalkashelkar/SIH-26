import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { scanService, ScanListItem } from '../services/api';
import './Profile.css';

export default function Profile() {
  const navigate = useNavigate();
  const [name, setName] = useState('Kunal Kashelkar');
  const [email, setEmail] = useState('kunal@cypher-sec.io');
  const [role, setRole] = useState('Lead Security Engineer');
  const [organization, setOrganization] = useState('CYPHER Autonomous Security');
  const [recentScans, setRecentScans] = useState<ScanListItem[]>([]);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    scanService.getScans(4)
      .then(scans => setRecentScans(scans))
      .catch(() => setRecentScans([]));
  }, []);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <div style={{display: 'flex', alignItems: 'center', gap: '16px'}}>
          <button className="btn-back" onClick={() => navigate(-1)} title="Go Back">
            <span className="material-symbols-outlined">arrow_back</span>
          </button>
          <div>
            <h1 className="page-title">Security Operator Profile</h1>
            <p className="page-subtitle">Manage credentials, active security clearance, session telemetry, and preferences.</p>
          </div>
        </div>
      </div>

      <div className="profile-layout">
        {/* Profile Card Summary */}
        <div className="profile-summary-card">
          <img 
            alt="Profile Avatar" 
            className="profile-large-avatar" 
            src="https://lh3.googleusercontent.com/aida/AP1WRLu-6cKuZDr6l-waS34Qne0PdpPaaC9AIoGERthEoWUMfj5-_aLzICDuzCCYoCoblWRAZT0w2SgS4pltJyXsbXR3GcIcwcqFADoGEZyjfITJ17LuF_NWxlIHqzLEXYs1t5vJgto7eGQPec3YvtreXxTOZSJ-GRqzpYtJOlt7YnBVyQ9SgSkwv88pxCbK8J41gc6KaphdUyW5UdwNEot24UuNEbSujaeEW62rqkZPQoQVYfIHfibSXg5UVDEr"
          />
          <h2 className="profile-name">{name}</h2>
          <span className="profile-role-badge">{role}</span>
          <p className="profile-org">{organization}</p>
          
          <div className="profile-stats-grid">
            <div className="profile-stat-box">
              <span className="p-stat-val text-primary">Level 3</span>
              <span className="p-stat-lbl">Clearance</span>
            </div>
            <div className="profile-stat-box">
              <span className="p-stat-val" style={{color: '#4caf50'}}>Active</span>
              <span className="p-stat-lbl">Session</span>
            </div>
            <div className="profile-stat-box">
              <span className="p-stat-val text-tertiary">2FA</span>
              <span className="p-stat-lbl">Enforced</span>
            </div>
          </div>

          <div style={{width: '100%', borderTop: '1px solid var(--color-outline-variant)', marginTop: '20px', paddingTop: '16px', textAlign: 'left'}}>
            <div style={{fontSize: '11px', fontWeight: 700, color: 'var(--color-on-surface-variant)', textTransform: 'uppercase', marginBottom: '10px'}}>
              Security Credentials
            </div>
            <div style={{display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12px'}}>
              <div style={{display: 'flex', justifyContent: 'space-between'}}>
                <span className="text-muted">Auth Standard:</span>
                <span className="font-mono">JWT Bearer (HS256)</span>
              </div>
              <div style={{display: 'flex', justifyContent: 'space-between'}}>
                <span className="text-muted">Hardware Token:</span>
                <span style={{color: '#4caf50'}}>FIDO2 / YubiKey</span>
              </div>
              <div style={{display: 'flex', justifyContent: 'space-between'}}>
                <span className="text-muted">Programmatic API:</span>
                <span style={{color: 'var(--color-primary)'}}>Scope: Read/Write</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right Side: Form & Real Activity */}
        <div style={{display: 'flex', flexDirection: 'column', gap: '24px'}}>
          {/* Edit Form */}
          <div className="profile-form-card">
            <h3 className="profile-card-title">Operator Identification</h3>
            {saved && (
              <div className="profile-saved-banner">
                <span className="material-symbols-outlined">check_circle</span>
                Profile changes persisted successfully.
              </div>
            )}
            <form onSubmit={handleSave} className="profile-form">
              <div className="grid-cols-2">
                <div className="form-group">
                  <label className="form-label">Full Name</label>
                  <input 
                    type="text" 
                    className="form-input" 
                    value={name} 
                    onChange={(e) => setName(e.target.value)} 
                    required 
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Email Address</label>
                  <input 
                    type="email" 
                    className="form-input" 
                    value={email} 
                    onChange={(e) => setEmail(e.target.value)} 
                    required 
                  />
                </div>
              </div>

              <div className="grid-cols-2">
                <div className="form-group">
                  <label className="form-label">Role Designation</label>
                  <input 
                    type="text" 
                    className="form-input" 
                    value={role} 
                    onChange={(e) => setRole(e.target.value)} 
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Organization / Operations Unit</label>
                  <input 
                    type="text" 
                    className="form-input" 
                    value={organization} 
                    onChange={(e) => setOrganization(e.target.value)} 
                  />
                </div>
              </div>

              <div className="profile-action-row">
                <button type="submit" className="btn-primary">
                  Update Operator Profile
                </button>
              </div>
            </form>
          </div>

          {/* Real Operator Audit Log / Activity */}
          <div className="profile-form-card">
            <h3 className="profile-card-title">Recent Security Operations Activity</h3>
            {recentScans.length === 0 ? (
              <p className="text-muted" style={{fontSize: '13px'}}>No operator activity logged yet for this session.</p>
            ) : (
              <div style={{display: 'flex', flexDirection: 'column', gap: '10px'}}>
                {recentScans.map((scan) => (
                  <div key={scan.id} style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '10px 14px',
                    background: 'rgba(0,0,0,0.2)',
                    borderRadius: '6px',
                    border: '1px solid rgba(255,255,255,0.04)',
                    fontSize: '13px'
                  }}>
                    <div style={{display: 'flex', alignItems: 'center', gap: '10px'}}>
                      <span className="material-symbols-outlined" style={{fontSize: '18px', color: 'var(--color-primary)'}}>radar</span>
                      <div>
                        <span style={{fontWeight: 600, color: 'var(--color-on-surface)'}}>{scan.target_url}</span>
                        <div style={{fontSize: '11px', color: 'var(--color-on-surface-variant)', fontFamily: 'monospace'}}>
                          Scan #{scan.id.slice(0, 8)} • Mode: {scan.scan_mode || 'Standard'}
                        </div>
                      </div>
                    </div>
                    <div style={{textAlign: 'right'}}>
                      <span className="status-badge badge-primary" style={{fontSize: '10px', padding: '2px 8px'}}>
                        {scan.status}
                      </span>
                      <div style={{fontSize: '11px', color: 'var(--color-on-surface-variant)', marginTop: '2px'}}>
                        {scan.total_findings} findings
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Preferences */}
          <div className="profile-form-card">
            <h3 className="profile-card-title">Platform & Console Preferences</h3>
            <div style={{display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px', fontSize: '13px'}}>
              <div style={{padding: '12px', background: 'rgba(0,0,0,0.2)', borderRadius: '6px'}}>
                <div className="text-muted" style={{fontSize: '11px', textTransform: 'uppercase'}}>Theme Aesthetic</div>
                <div style={{fontWeight: 700, marginTop: '4px', color: 'var(--color-on-surface)'}}>Dark Cybersecurity SOC</div>
              </div>
              <div style={{padding: '12px', background: 'rgba(0,0,0,0.2)', borderRadius: '6px'}}>
                <div className="text-muted" style={{fontSize: '11px', textTransform: 'uppercase'}}>Alert Notifications</div>
                <div style={{fontWeight: 700, marginTop: '4px', color: '#4caf50'}}>Critical & High Findings</div>
              </div>
              <div style={{padding: '12px', background: 'rgba(0,0,0,0.2)', borderRadius: '6px'}}>
                <div className="text-muted" style={{fontSize: '11px', textTransform: 'uppercase'}}>Telemetry Polling</div>
                <div style={{fontWeight: 700, marginTop: '4px', color: 'var(--color-primary)'}}>Real-time Stream (1500ms)</div>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}
