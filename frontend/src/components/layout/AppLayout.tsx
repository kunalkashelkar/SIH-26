import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import Topbar from './Topbar';

export default function AppLayout() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <div className={`app-layout ${mobileMenuOpen ? 'mobile-sidebar-open' : ''}`}>
      {/* Mobile Backdrop */}
      {mobileMenuOpen && (
        <div 
          className="mobile-backdrop" 
          onClick={() => setMobileMenuOpen(false)}
        />
      )}
      
      <Sidebar onCloseMobile={() => setMobileMenuOpen(false)} />
      
      <div className="app-content-wrapper">
        <Topbar onToggleMobileMenu={() => setMobileMenuOpen(!mobileMenuOpen)} />
        <main className="app-main">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
