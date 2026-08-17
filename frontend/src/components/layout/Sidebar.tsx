import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';

export default function Sidebar() {
  const navigate = useNavigate();

  return (
    <aside className="app-sidebar">
      <div className="sidebar-header">
        <img 
          alt="Sentinel Logo" 
          className="sidebar-logo" 
          src="https://lh3.googleusercontent.com/aida/AP1WRLuwerRDvsobOivIzvDdFN-sM1KgDiEZ6mYfN72dgWjbgZmLTSehFOk3Mig4sauj8U0qb7htzCYIdLlHgpE0RD69kJyyVOG9TTa38FuWh7pbNPMBo-G5Hv1NFDM0IgTzVTAIe7gPKwr5wdhjY4QKu7hDZW4YiH1OrySkQxFAehC6PvRyb7PJnOX1oydZ8Vof895l2B2x6TGU5zWgJ8QP4GY9EK_YIITdWY1BLdbDt1VnQbsq7LQKwtfz6IJs"
        />
        <span className="sidebar-brand">Sentinel</span>
      </div>
      
      <nav className="sidebar-nav">
        <div className="nav-section">
          <NavLink to="/dashboard" className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
            <span className="material-symbols-outlined icon-small">dashboard</span>Dashboard
          </NavLink>
          <NavLink to="/scans" className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
            <span className="material-symbols-outlined icon-small">manage_search</span>Scans
          </NavLink>
          <NavLink to="/attack-surface" className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
            <span className="material-symbols-outlined icon-small">hub</span>Attack Surface
          </NavLink>
          <NavLink to="/findings" className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
            <span className="material-symbols-outlined icon-small">security</span>Findings
          </NavLink>
          <NavLink to="/fuzzing" className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
            <span className="material-symbols-outlined icon-small">experiment</span>Fuzzing
          </NavLink>
          <NavLink to="/reports" className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
            <span className="material-symbols-outlined icon-small">assessment</span>Reports
          </NavLink>
        </div>
        
        <div className="nav-divider"></div>
        
        <div className="nav-section">
          <NavLink to="/projects" className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
            <span className="material-symbols-outlined icon-small">folder</span>Projects
          </NavLink>
          <NavLink to="/targets" className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
            <span className="material-symbols-outlined icon-small">target</span>Targets
          </NavLink>
          <NavLink to="/payloads" className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
            <span className="material-symbols-outlined icon-small">code</span>Payloads
          </NavLink>
          <NavLink to="/settings" className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
            <span className="material-symbols-outlined icon-small">settings</span>Settings
          </NavLink>
          <NavLink to="/documentation" className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
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
