import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './Profile.css';

export default function Profile() {
  const navigate = useNavigate();
  const [name, setName] = useState('Kunal Kashelkar');
  const [email, setEmail] = useState('kunal@cypher-sec.io');
  const [role, setRole] = useState('Lead Security Engineer');
  const [organization, setOrganization] = useState('CYPHER Autonomous Security');
  const [saved, setSaved] = useState(false);

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
            <h1 className="page-title">User Profile</h1>
            <p className="page-subtitle">Manage your personal credentials, active security clearance, and session details.</p>
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
              <span className="p-stat-val text-primary">Admin</span>
              <span className="p-stat-lbl">Role</span>
            </div>
            <div className="profile-stat-box">
              <span className="p-stat-val">Active</span>
              <span className="p-stat-lbl">Status</span>
            </div>
            <div className="profile-stat-box">
              <span className="p-stat-val text-tertiary">2FA</span>
              <span className="p-stat-lbl">Secured</span>
            </div>
          </div>
        </div>

        {/* Edit Form */}
        <div className="profile-form-card">
          <h3 className="profile-card-title">Security Operator Information</h3>
          {saved && (
            <div className="profile-saved-banner">
              <span className="material-symbols-outlined">check_circle</span>
              Profile information updated successfully.
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
                <label className="form-label">Organization</label>
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
                Save Profile Changes
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
