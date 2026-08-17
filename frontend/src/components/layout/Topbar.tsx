import React from 'react';
import { useNavigate } from 'react-router-dom';

export default function Topbar() {
  const navigate = useNavigate();

  return (
    <header className="app-topbar">
      <div className="topbar-search-container">
        <div className="search-input-wrapper">
          <span className="material-symbols-outlined search-icon">search</span>
          <input 
            type="text" 
            className="search-input" 
            placeholder="Search endpoints, scans, findings..." 
          />
        </div>
      </div>
      
      <div className="topbar-actions">

        <button className="btn-icon">
          <span className="material-symbols-outlined">notifications</span>
        </button>
        
        <button className="btn-icon">
          <span className="material-symbols-outlined">help</span>
        </button>
        
        <img 
          alt="Profile" 
          className="profile-avatar" 
          src="https://lh3.googleusercontent.com/aida/AP1WRLu-6cKuZDr6l-waS34Qne0PdpPaaC9AIoGERthEoWUMfj5-_aLzICDuzCCYoCoblWRAZT0w2SgS4pltJyXsbXR3GcIcwcqFADoGEZyjfITJ17LuF_NWxlIHqzLEXYs1t5vJgto7eGQPec3YvtreXxTOZSJ-GRqzpYtJOlt7YnBVyQ9SgSkwv88pxCbK8J41gc6KaphdUyW5UdwNEot24UuNEbSujaeEW62rqkZPQoQVYfIHfibSXg5UVDEr"
        />
      </div>
    </header>
  );
}
