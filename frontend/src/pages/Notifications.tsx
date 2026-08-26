import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './Notifications.css';

interface NotificationItem {
  id: string;
  title: string;
  message: string;
  time: string;
  type: 'security' | 'scan' | 'system';
  unread: boolean;
}

export default function Notifications() {
  const navigate = useNavigate();
  const [notifications, setNotifications] = useState<NotificationItem[]>([
    {
      id: '1',
      title: 'Vulnerability Confirmed',
      message: 'High severity SQL Injection vulnerability verified on target endpoint /api/auth/login.',
      time: '10 minutes ago',
      type: 'security',
      unread: true,
    },
    {
      id: '2',
      title: 'Scan Pipeline Finished',
      message: 'Scan SCN-8842 completed attack surface discovery and ML vulnerability inference.',
      time: '1 hour ago',
      type: 'scan',
      unread: true,
    },
    {
      id: '3',
      title: 'ML Model Inference Complete',
      message: 'XGBoost engine classified 19 endpoint parameters with high confidence ROC-AUC: 0.996.',
      time: '3 hours ago',
      type: 'system',
      unread: false,
    },
    {
      id: '4',
      title: 'PostgreSQL Database Synchronized',
      message: 'Attack graph nodes and relationships synchronized with active scan state.',
      time: '1 day ago',
      type: 'system',
      unread: false,
    }
  ]);

  const markAllRead = () => {
    setNotifications(prev => prev.map(n => ({ ...n, unread: false })));
  };

  const clearAll = () => {
    setNotifications([]);
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <div style={{display: 'flex', alignItems: 'center', gap: '16px'}}>
          <button className="btn-back" onClick={() => navigate(-1)} title="Go Back">
            <span className="material-symbols-outlined">arrow_back</span>
          </button>
          <div>
            <h1 className="page-title">Notifications</h1>
            <p className="page-subtitle">Real-time alerts, scan completions, and security intelligence events.</p>
          </div>
        </div>
        <div style={{display: 'flex', gap: '10px'}}>
          <button className="btn-outline-small" onClick={markAllRead}>
            Mark All Read
          </button>
          <button className="btn-outline-small" onClick={clearAll} style={{color: 'var(--color-error)'}}>
            Clear All
          </button>
        </div>
      </div>

      <div className="notifications-list">
        {notifications.length === 0 ? (
          <div className="notifications-empty">
            <span className="material-symbols-outlined" style={{fontSize: '48px', color: 'var(--color-on-surface-variant)'}}>notifications_off</span>
            <p style={{color: 'var(--color-on-surface-variant)', marginTop: '12px'}}>No notifications at this time.</p>
          </div>
        ) : (
          notifications.map(n => (
            <div key={n.id} className={`notification-item ${n.unread ? 'unread' : ''}`}>
              <div className={`notification-icon-box icon-${n.type}`}>
                <span className="material-symbols-outlined">
                  {n.type === 'security' ? 'security' : n.type === 'scan' ? 'radar' : 'dns'}
                </span>
              </div>
              <div className="notification-content">
                <div className="notification-title-row">
                  <span className="notification-title">{n.title}</span>
                  <span className="notification-time">{n.time}</span>
                </div>
                <p className="notification-message">{n.message}</p>
              </div>
              {n.unread && <span className="unread-dot"></span>}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
