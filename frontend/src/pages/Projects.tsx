import React from 'react';
import './Projects.css';

export default function Projects() {
  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title m-0">Projects</h1>
          <p className="page-subtitle mt-2">Manage your target applications and scan environments.</p>
        </div>
        <button className="btn-primary flex items-center gap-2 shadow-sm">
          <span className="material-symbols-outlined text-[20px]">add</span>
          New Project
        </button>
      </div>
      
      <div className="projects-grid">
        {/* Project Card: E-Commerce API */}
        <div className="project-card group">
          <div className="project-card-glow glow-error"></div>
          <div className="project-card-header">
            <div className="flex items-center gap-3">
              <div className="project-icon-container">
                <span className="material-symbols-outlined">shopping_cart</span>
              </div>
              <div>
                <h2 className="project-title m-0">E-Commerce API</h2>
                <span className="project-subtitle">api.prod.example.com</span>
              </div>
            </div>
            <button className="btn-icon-transparent">
              <span className="material-symbols-outlined text-[20px]">more_vert</span>
            </button>
          </div>
          
          <div className="project-metrics">
            <div className="metric">
              <span className="metric-label">Scans</span>
              <span className="metric-value">12</span>
            </div>
            <div className="metric">
              <span className="metric-label">Findings</span>
              <span className="metric-value text-error">23</span>
            </div>
            <div className="metric">
              <span className="metric-label">Risk Score</span>
              <div className="flex items-baseline gap-1">
                <span className="metric-value text-error">7.2</span>
                <span className="metric-subtext text-error">/10</span>
              </div>
            </div>
          </div>
          
          <div className="project-trend">
            <div className="flex justify-between items-center mb-2">
              <span className="trend-label">Risk Trend (30d)</span>
              <span className="trend-value text-error flex items-center gap-1">
                <span className="material-symbols-outlined text-[14px]">trending_up</span> +1.2
              </span>
            </div>
            <svg className="w-full h-12 text-error" preserveAspectRatio="none" viewBox="0 0 200 40">
              <path d="M0,35 L40,30 L80,38 L120,20 L160,25 L200,5" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"></path>
              <path d="M0,35 L40,30 L80,38 L120,20 L160,25 L200,5 L200,40 L0,40 Z" fill="currentColor" fillOpacity="0.1"></path>
            </svg>
          </div>
          
          <div className="project-tags">
            <span className="project-tag">Production</span>
            <span className="project-tag">PCI-DSS</span>
          </div>
        </div>

        {/* Project Card: Banking Portal */}
        <div className="project-card group">
          <div className="project-card-glow glow-tertiary"></div>
          <div className="project-card-header">
            <div className="flex items-center gap-3">
              <div className="project-icon-container">
                <span className="material-symbols-outlined">account_balance</span>
              </div>
              <div>
                <h2 className="project-title m-0">Banking Portal</h2>
                <span className="project-subtitle">portal.bank.internal</span>
              </div>
            </div>
            <button className="btn-icon-transparent">
              <span className="material-symbols-outlined text-[20px]">more_vert</span>
            </button>
          </div>
          
          <div className="project-metrics">
            <div className="metric">
              <span className="metric-label">Scans</span>
              <span className="metric-value">8</span>
            </div>
            <div className="metric">
              <span className="metric-label">Findings</span>
              <span className="metric-value text-tertiary">11</span>
            </div>
            <div className="metric">
              <span className="metric-label">Risk Score</span>
              <div className="flex items-baseline gap-1">
                <span className="metric-value text-tertiary">4.1</span>
                <span className="metric-subtext text-tertiary">/10</span>
              </div>
            </div>
          </div>
          
          <div className="project-trend">
            <div className="flex justify-between items-center mb-2">
              <span className="trend-label">Risk Trend (30d)</span>
              <span className="trend-value text-muted flex items-center gap-1">
                <span className="material-symbols-outlined text-[14px]">trending_flat</span> 0.0
              </span>
            </div>
            <svg className="w-full h-12 text-tertiary" preserveAspectRatio="none" viewBox="0 0 200 40">
              <path d="M0,20 L40,25 L80,22 L120,28 L160,20 L200,20" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"></path>
              <path d="M0,20 L40,25 L80,22 L120,28 L160,20 L200,20 L200,40 L0,40 Z" fill="currentColor" fillOpacity="0.1"></path>
            </svg>
          </div>
          
          <div className="project-tags">
            <span className="project-tag">Staging</span>
            <span className="project-tag">Internal</span>
          </div>
        </div>

        {/* Add New Project Card */}
        <div className="project-card-new">
          <div className="project-card-new-icon">
            <span className="material-symbols-outlined text-[32px]">add</span>
          </div>
          <h3 className="project-title m-0 text-center">Create New Project</h3>
          <p className="project-card-new-desc">Set up a new target environment for continuous scanning.</p>
        </div>
      </div>
    </div>
  );
}
