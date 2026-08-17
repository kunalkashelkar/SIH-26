import React from 'react';
import './Targets.css';

export default function Targets() {
  return (
    <div className="page-container">
      <div className="targets-header">
        <div className="targets-title-group">
          <h1 className="page-title m-0 mb-1">Target Inventory</h1>
          <p className="page-subtitle m-0">Manage and monitor your defined scanning targets and their associated risk profiles.</p>
        </div>
        <button className="btn-primary font-caps shadow-sm">
          <span className="material-symbols-outlined text-[18px] mr-2">add</span>
          Add Target
        </button>
      </div>

      <div className="targets-table-container">
        <div className="targets-toolbar">
          <div className="targets-search">
            <span className="material-symbols-outlined">filter_list</span>
            <input 
              type="text" 
              className="targets-search-input" 
              placeholder="Filter targets..." 
            />
          </div>
          <div className="flex items-center gap-4">
            <span className="font-body-sm text-muted">Showing 4 targets</span>
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
            <tr>
              <td className="font-mono-sm text-primary">api.production.internal</td>
              <td className="font-body-sm text-muted">2 hours ago</td>
              <td className="font-mono-md text-right">142</td>
              <td>
                <span className="status-badge-inline critical">
                  <span className="material-symbols-outlined text-[14px]">warning</span> Critical
                </span>
              </td>
              <td className="text-right">
                <button className="table-action-btn primary">Scan</button>
                <button className="table-action-btn secondary">Edit</button>
                <button className="table-action-btn error">Delete</button>
              </td>
            </tr>
            
            <tr className="stripe">
              <td className="font-mono-sm text-primary">auth-gateway.vpc-east.net</td>
              <td className="font-body-sm text-muted">Yesterday, 14:30</td>
              <td className="font-mono-md text-right">18</td>
              <td>
                <span className="status-badge-inline high">
                  <span className="material-symbols-outlined text-[14px]">error</span> High
                </span>
              </td>
              <td className="text-right">
                <button className="table-action-btn primary">Scan</button>
                <button className="table-action-btn secondary">Edit</button>
                <button className="table-action-btn error">Delete</button>
              </td>
            </tr>

            <tr>
              <td className="font-mono-sm text-primary">legacy-billing.corp.local</td>
              <td className="font-body-sm text-muted">Oct 12, 2023</td>
              <td className="font-mono-md text-right">5</td>
              <td>
                <span className="status-badge-inline medium">
                  <span className="material-symbols-outlined text-[14px]">info</span> Medium
                </span>
              </td>
              <td className="text-right">
                <button className="table-action-btn primary">Scan</button>
                <button className="table-action-btn secondary">Edit</button>
                <button className="table-action-btn error">Delete</button>
              </td>
            </tr>

            <tr className="stripe">
              <td className="font-mono-sm text-primary">cdn-edge-nodes.global</td>
              <td className="font-body-sm text-muted">3 mins ago</td>
              <td className="font-mono-md text-right">0</td>
              <td>
                <span className="status-badge-inline low">
                  <span className="material-symbols-outlined text-[14px]">check_circle</span> Low
                </span>
              </td>
              <td className="text-right">
                <button className="table-action-btn primary">Scan</button>
                <button className="table-action-btn secondary">Edit</button>
                <button className="table-action-btn error">Delete</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}
