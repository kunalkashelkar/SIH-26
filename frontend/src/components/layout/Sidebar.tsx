import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';

interface SidebarProps {
  onCloseMobile?: () => void;
}

export default function Sidebar({ onCloseMobile }: SidebarProps) {
  const navigate = useNavigate();

  const handleNavClick = () => {
    if (onCloseMobile) {
      onCloseMobile();
    }
  };

  return (
    <aside className="app-sidebar">
      <div className="sidebar-header">
        <img 
          alt="CYPHER Logo" 
          className="sidebar-logo" 
          src="https://lh3.googleusercontent.com/aida/AP1WRLuwerRDvsobOivIzvDdFN-sM1KgDiEZ6mYfN72dgWjbgZmLTSehFOk3Mig4sauj8U0qb7htzCYIdLlHgpE0RD69kJyyVOG9TTa38FuWh7pbNPMBo-G5Hv1NFDM0IgTzVTAIe7gPKwr5wdhjY4QKu7hDZW4YiH1OrySkQxFAehC6PvRyb7PJnOX1oydZ8Vof895l2B2x6TGU5zWgJ8QP4GY9EK_YIITdWY1BLdbDt1VnQbsq7LQKwtfz6IJs"
        />
        <span className="sidebar-brand">CYPHER</span>
        {onCloseMobile && (
          <button className="mobile-sidebar-close" onClick={onCloseMobile}>✕</button>
        )}
      </div>
      
      <nav className="sidebar-nav">
        <div className="nav-section">
          <div className="nav-section-title">OPERATIONS</div>
          <NavLink to="/dashboard" onClick={handleNavClick} className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
            <span className="material-symbols-outlined icon-small">dashboard</span>Dashboard
          </NavLink>
          <NavLink to="/scans" onClick={handleNavClick} className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
            <span className="material-symbols-outlined icon-small">manage_search</span>Scans
          </NavLink>
          <NavLink to="/attack-surface" onClick={handleNavClick} className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
            <span className="material-symbols-outlined icon-small">hub</span>Attack Surface
          </NavLink>
          <NavLink to="/findings" onClick={handleNavClick} className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
            <span className="material-symbols-outlined icon-small">security</span>Findings
          </NavLink>
          <NavLink to="/fuzzing" onClick={handleNavClick} className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
            <span className="material-symbols-outlined icon-small">science</span>Fuzzing
          </NavLink>
          <NavLink to="/reports" onClick={handleNavClick} className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
            <span className="material-symbols-outlined icon-small">assessment</span>Reports
          </NavLink>
        </div>
        
        <div className="nav-divider"></div>
        
        <div className="nav-section">
          <div className="nav-section-title">MANAGEMENT</div>
          <NavLink to="/projects" onClick={handleNavClick} className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
            <span className="material-symbols-outlined icon-small">folder</span>Projects
          </NavLink>
          <NavLink to="/targets" onClick={handleNavClick} className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
            <span className="material-symbols-outlined icon-small">radar</span>Targets
          </NavLink>
          <NavLink to="/payloads" onClick={handleNavClick} className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
            <span className="material-symbols-outlined icon-small">code</span>Payloads
          </NavLink>
        </div>

        <div className="nav-divider"></div>

        <div className="nav-section">
          <div className="nav-section-title">SYSTEM</div>
          <NavLink to="/settings" onClick={handleNavClick} className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
            <span className="material-symbols-outlined icon-small">settings</span>Settings
          </NavLink>
          <NavLink to="/documentation" onClick={handleNavClick} className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
            <span className="material-symbols-outlined icon-small">menu_book</span>Documentation
          </NavLink>
        </div>
      </nav>
      
      <div className="sidebar-footer">
        <button className="nav-item nav-item-danger" onClick={() => navigate('/login')}>
          <span className="material-symbols-outlined icon-small">logout</span>Logout
        </button>
      </div>
    </aside>
  );
}
