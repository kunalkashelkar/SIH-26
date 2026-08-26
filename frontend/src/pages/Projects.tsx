import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { projectService, ProjectItem } from '../services/api';
import './Projects.css';

export default function Projects() {
  const navigate = useNavigate();
  const [projects, setProjects] = useState<ProjectItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [showModal, setShowModal] = useState<boolean>(false);
  const [name, setName] = useState<string>('');
  const [desc, setDesc] = useState<string>('');
  const [submitting, setSubmitting] = useState<boolean>(false);

  const loadProjects = async () => {
    try {
      setLoading(true);
      const data = await projectService.getProjects();
      setProjects(data);
    } catch (e) {
      console.warn("Failed to load projects:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadProjects();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name) return;
    try {
      setSubmitting(true);
      await projectService.createProject({ name, description: desc });
      setName('');
      setDesc('');
      setShowModal(false);
      await loadProjects();
    } catch (err: any) {
      alert(`Failed to create project: ${err.message || err}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (projectId: string) => {
    if (!window.confirm("Are you sure you want to delete this target application workspace?")) return;
    try {
      await projectService.deleteProject(projectId);
      await loadProjects();
    } catch (err: any) {
      alert(`Failed to delete project: ${err.message || err}`);
    }
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <div style={{display: 'flex', alignItems: 'center', gap: '16px'}}>
          <button className="btn-back" onClick={() => navigate(-1)} title="Go Back">
            <span className="material-symbols-outlined">arrow_back</span>
          </button>
          <div>
            <h1 className="page-title m-0">Target Project Workspaces</h1>
            <p className="page-subtitle mt-1">Organize websites, internal APIs, and scan environments under CYPHER workspaces.</p>
          </div>
        </div>
        <button className="btn-primary flex items-center gap-2 shadow-sm" onClick={() => setShowModal(true)}>
          <span className="material-symbols-outlined text-[20px]">add</span>
          New Project
        </button>
      </div>

      {showModal && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.7)', zIndex: 1000,
          display: 'flex', alignItems: 'center', justifyContent: 'center'
        }}>
          <div className="card" style={{maxWidth: '480px', width: '100%', padding: '24px', background: 'var(--color-surface)', borderRadius: '12px', border: '1px solid var(--color-outline-variant)'}}>
            <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px'}}>
              <h2 style={{margin: 0, fontSize: '18px', fontWeight: 700}}>Create Project Workspace</h2>
              <button className="btn-icon-transparent" onClick={() => setShowModal(false)}>
                <span className="material-symbols-outlined">close</span>
              </button>
            </div>
            <form onSubmit={handleCreate}>
              <div style={{marginBottom: '16px'}}>
                <label className="form-label">Project / Target Domain Name *</label>
                <input 
                  type="text" 
                  className="form-input" 
                  placeholder="e.g. Fintech Core API" 
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required 
                />
              </div>
              <div style={{marginBottom: '20px'}}>
                <label className="form-label">Scope & Architecture Notes</label>
                <textarea 
                  className="form-input" 
                  rows={3}
                  placeholder="e.g. Production microservices, OAuth endpoints, staging endpoints..."
                  value={desc}
                  onChange={(e) => setDesc(e.target.value)}
                />
              </div>
              <div style={{display: 'flex', justifyContent: 'flex-end', gap: '12px'}}>
                <button type="button" className="btn-link" onClick={() => setShowModal(false)}>Cancel</button>
                <button type="submit" className="btn-primary" disabled={submitting}>
                  {submitting ? 'Creating...' : 'Create Project'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
      
      <div className="projects-grid">
        {loading ? (
          <div style={{gridColumn: 'span 3', padding: '32px', textAlign: 'center', color: 'var(--color-on-surface-variant)'}}>
            Loading project environments...
          </div>
        ) : projects.length === 0 ? (
          <div style={{gridColumn: 'span 3', padding: '32px', textAlign: 'center', color: 'var(--color-on-surface-variant)'}}>
            No target projects configured yet. Click "New Project" to define your first scan scope.
          </div>
        ) : (
          projects.map((proj) => {
            const glowClass = proj.risk_score >= 7 ? 'glow-error' : proj.risk_score >= 4 ? 'glow-tertiary' : 'glow-primary';
            const textClass = proj.risk_score >= 7 ? 'text-error' : proj.risk_score >= 4 ? 'text-tertiary' : 'text-primary';
            
            return (
              <div key={proj.id} className="project-card group">
                <div className={`project-card-glow ${glowClass}`}></div>
                <div className="project-card-header">
                  <div className="flex items-center gap-3">
                    <div className="project-icon-container">
                      <span className="material-symbols-outlined">folder</span>
                    </div>
                    <div>
                      <h2 className="project-title m-0">{proj.name}</h2>
                      <span className="project-subtitle">{proj.description || 'Active security monitoring target'}</span>
                    </div>
                  </div>
                  <button className="btn-icon-transparent" onClick={() => handleDelete(proj.id)} title="Delete Project">
                    <span className="material-symbols-outlined text-[20px]" style={{color: 'var(--color-error)'}}>delete</span>
                  </button>
                </div>
                
                <div className="project-card-body">
                  <div className="project-stat-box">
                    <span className="stat-label font-caps">Targets</span>
                    <span className="stat-value font-mono">{proj.total_targets}</span>
                  </div>
                  <div className="project-stat-box">
                    <span className="stat-label font-caps">Scans Executed</span>
                    <span className="stat-value font-mono">{proj.total_scans}</span>
                  </div>
                  <div className="project-stat-box">
                    <span className="stat-label font-caps">Risk Rating</span>
                    <span className={`stat-value font-mono ${textClass}`}>
                      {proj.risk_score > 0 ? proj.risk_score.toFixed(1) : 'Safe'}
                    </span>
                  </div>
                </div>

                <div className="project-card-footer">
                  <button className="btn-project-action" onClick={() => navigate('/targets')}>
                    <span>Manage Targets</span>
                    <span className="material-symbols-outlined text-[16px]">arrow_forward</span>
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
