import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { healthService, SystemHealth } from '../../services/api';

interface TopbarProps {
  onToggleMobileMenu?: () => void;
}

export default function Topbar({ onToggleMobileMenu }: TopbarProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [showHealthModal, setShowHealthModal] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    async function checkHealth() {
      try {
        const res = await healthService.getHealth();
        setHealth(res);
      } catch (err) {
        console.warn("System health check warning:", err);
      }
    }
    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const isHealthy = health?.status === 'ok';

  // Compute Page Context Breadcrumb
  const getPageTitle = (path: string) => {
    if (path.startsWith('/dashboard')) return 'Dashboard';
    if (path.startsWith('/scans/new')) return 'New Security Scan';
    if (path.includes('/attack-surface')) return 'Attack Surface Graph';
    if (path.includes('/fuzzing')) return 'Adaptive Fuzzing';
    if (path.includes('/findings')) return 'Security Findings';
    if (path.startsWith('/scans')) return 'Scans & Live Execution';
    if (path.startsWith('/vulnerabilities')) return 'Vulnerability Investigation';
    if (path.startsWith('/reports')) return 'Security Audit Reports';
    if (path.startsWith('/projects')) return 'Project Workspaces';
    if (path.startsWith('/targets')) return 'Target Inventory';
    if (path.startsWith('/payloads')) return 'Payload Repository';
    if (path.startsWith('/settings')) return 'System Settings';
    if (path.startsWith('/documentation')) return 'Architecture & Docs';
    if (path.startsWith('/profile')) return 'Operator Profile';
    if (path.startsWith('/notifications')) return 'Notification Center';
    return 'Console';
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      navigate(`/findings?q=${encodeURIComponent(searchQuery.trim())}`);
    }
  };

  return (
    <header className="app-topbar">
      <div className="topbar-left-wrapper">
        {onToggleMobileMenu && (
          <button 
            className="mobile-hamburger-btn" 
            onClick={onToggleMobileMenu}
            title="Toggle Navigation Menu"
          >
            <span className="material-symbols-outlined">menu</span>
          </button>
        )}
        <div className="topbar-breadcrumb">
          <span className="breadcrumb-brand">CYPHER</span>
          <span className="breadcrumb-separator">/</span>
          <span className="breadcrumb-page">{getPageTitle(location.pathname)}</span>
        </div>
      </div>

      <div className="topbar-search-container">
        <form onSubmit={handleSearchSubmit} className="search-input-wrapper">
          <span className="material-symbols-outlined search-icon">search</span>
          <input 
            type="text" 
            className="search-input" 
            placeholder="Search endpoints, scans, findings (Press Enter)..." 
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </form>
      </div>
      
      <div className="topbar-actions">
        {/* Real System Health Indicator */}
        <div 
          style={{
            display: 'flex', 
            alignItems: 'center', 
            gap: '8px', 
            padding: '4px 10px', 
            borderRadius: '16px', 
            background: isHealthy ? 'rgba(76, 175, 80, 0.1)' : 'rgba(255, 152, 0, 0.1)', 
            border: `1px solid ${isHealthy ? 'rgba(76, 175, 80, 0.3)' : 'rgba(255, 152, 0, 0.3)'}`,
            cursor: 'pointer',
            fontSize: '12px',
            fontWeight: 600,
            color: isHealthy ? '#4caf50' : '#ff9800'
          }}
          onClick={() => setShowHealthModal(!showHealthModal)}
          title="Click to view live system engine health"
        >
          <span className="status-dot" style={{background: isHealthy ? '#4caf50' : '#ff9800'}}></span>
          <span>{isHealthy ? 'System Online' : 'System Degraded'}</span>
          <span className="material-symbols-outlined" style={{fontSize: '14px'}}>info</span>
        </div>

        {showHealthModal && (
          <div style={{
            position: 'absolute',
            top: '56px',
            right: '80px',
            width: '280px',
            background: 'var(--color-surface-container-high)',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            borderRadius: '8px',
            padding: '16px',
            boxShadow: '0 8px 24px rgba(0,0,0,0.5)',
            zIndex: 1000,
            fontSize: '13px'
          }}>
            <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px'}}>
              <strong style={{color: 'var(--color-on-surface)'}}>Live Infrastructure Status</strong>
              <button onClick={() => setShowHealthModal(false)} style={{background: 'none', border: 'none', color: 'var(--color-on-surface-variant)', cursor: 'pointer'}}>✕</button>
            </div>
            <div style={{display: 'flex', flexDirection: 'column', gap: '8px'}}>
              <div style={{display: 'flex', justifyContent: 'space-between'}}>
                <span className="text-muted">PostgreSQL DB:</span>
                <span style={{color: health?.components?.database === 'connected' ? '#4caf50' : '#f44336', fontWeight: 600}}>
                  {health?.components?.database || 'checking...'}
                </span>
              </div>
              <div style={{display: 'flex', justifyContent: 'space-between'}}>
                <span className="text-muted">XGBoost Model:</span>
                <span style={{color: health?.components?.ml_model === 'loaded' ? '#4caf50' : '#ff9800', fontWeight: 600}}>
                  {health?.components?.ml_model || 'checking...'}
                </span>
              </div>
              <div style={{display: 'flex', justifyContent: 'space-between'}}>
                <span className="text-muted">ML Preprocessor:</span>
                <span style={{color: health?.components?.preprocessor === 'loaded' ? '#4caf50' : '#ff9800', fontWeight: 600}}>
                  {health?.components?.preprocessor || 'checking...'}
                </span>
              </div>
              <div style={{display: 'flex', justifyContent: 'space-between'}}>
                <span className="text-muted">Scanner Core:</span>
                <span style={{color: health?.components?.scanner === 'ready' ? '#4caf50' : '#ff9800', fontWeight: 600}}>
                  {health?.components?.scanner || 'checking...'}
                </span>
              </div>
            </div>
          </div>
        )}

        <button className="btn-icon" onClick={() => navigate('/notifications')} title="Notifications">
          <span className="material-symbols-outlined">notifications</span>
        </button>
        
        <button className="btn-icon" onClick={() => navigate('/settings')} title="Settings">
          <span className="material-symbols-outlined">settings</span>
        </button>
        
        <img 
          alt="Profile" 
          className="profile-avatar cursor-pointer" 
          style={{cursor: 'pointer'}}
          title="View Profile"
          onClick={() => navigate('/profile')}
          src="https://lh3.googleusercontent.com/aida/AP1WRLu-6cKuZDr6l-waS34Qne0PdpPaaC9AIoGERthEoWUMfj5-_aLzICDuzCCYoCoblWRAZT0w2SgS4pltJyXsbXR3GcIcwcqFADoGEZyjfITJ17LuF_NWxlIHqzLEXYs1t5vJgto7eGQPec3YvtreXxTOZSJ-GRqzpYtJOlt7YnBVyQ9SgSkwv88pxCbK8J41gc6KaphdUyW5UdwNEot24UuNEbSujaeEW62rqkZPQoQVYfIHfibSXg5UVDEr"
        />
      </div>
    </header>
  );
}

