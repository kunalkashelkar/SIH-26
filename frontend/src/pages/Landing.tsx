import React from 'react';
import { Link } from 'react-router-dom';

export default function Landing() {
  return (
    <div className="landing-page">
      <main className="landing-main">
        <div className="landing-container">
          <div className="background-grid"></div>
          
          <section className="hero-section">
            <div className="release-badge">
              <span className="dot"></span>
              <span className="badge-text">Sentinel Core v2.4 Released</span>
            </div>
            
            <h1 className="hero-title">
              Intelligent Web Application <span className="highlight">Security Testing</span>
            </h1>
            
            <p className="hero-subtitle">
              Discover your attack surface. Prioritize what matters. Fuzz intelligently. Validate vulnerabilities.
            </p>
            
            <div className="cta-container">
              <Link to="/login" className="btn-primary" style={{ textDecoration: 'none' }}>
                <span className="material-symbols-outlined">radar</span>
                Start Scanning
              </Link>
              <button className="btn-secondary">
                <span className="material-symbols-outlined">menu_book</span>
                View Documentation
              </button>
            </div>
            
            <div className="terminal-window">
              <div className="terminal-header">
                <div className="traffic-lights">
                  <div className="light"></div>
                  <div className="light"></div>
                  <div className="light"></div>
                </div>
                <div className="terminal-title">sentinel-scan --target https://example.com</div>
              </div>
              <div className="terminal-body">
                <pre className="terminal-text">
<span className="terminal-plus">[+]</span> Initializing target scope: example.com
<span className="terminal-plus">[+]</span> Active discovery module loaded (hybrid mode)
<span className="terminal-asterisk">[*]</span> Found 142 unique endpoints
<span className="terminal-asterisk">[*]</span> Building Attack Surface Graph... <span className="terminal-dim">Done (42ms)</span>
<span className="terminal-plus">[+]</span> Prioritizing high-risk vectors
<span className="terminal-error">[!]</span> Critical vulnerability detected: SQL Injection (SQLi)
    <span className="terminal-muted">Path: /api/v1/users?id=1' OR '1'='1</span>
    <span className="terminal-muted">Confidence: 99%</span>
<span className="terminal-dim">[+]</span> Validation successful. Exploit confirmed.</pre>
                <div className="terminal-fade"></div>
              </div>
            </div>
          </section>
          
          <section className="pipeline-section">
            <div className="pipeline-container">
              <div className="pipeline-header">
                <h2 className="section-title">The Sentinel Pipeline</h2>
                <p className="section-subtitle">A deterministic approach to uncovering critical security flaws before they reach production.</p>
              </div>
              
              <div className="pipeline-grid">
                <div className="pipeline-line"></div>
                
                <div className="pipeline-stage">
                  <div className="stage-icon-container">
                    <span className="material-symbols-outlined stage-icon">search</span>
                  </div>
                  <h3 className="stage-title">DISCOVER</h3>
                  <p className="stage-desc">Deep crawling and parameter extraction</p>
                </div>
                
                <div className="pipeline-stage">
                  <div className="stage-icon-container">
                    <span className="material-symbols-outlined stage-icon">schema</span>
                  </div>
                  <h3 className="stage-title">MAP</h3>
                  <p className="stage-desc">Build internal state and logic graph</p>
                </div>
                
                <div className="pipeline-stage">
                  <div className="stage-icon-container">
                    <span className="material-symbols-outlined stage-icon">sort</span>
                  </div>
                  <h3 className="stage-title">PRIORITIZE</h3>
                  <p className="stage-desc">Rank vectors by expected impact</p>
                </div>
                
                <div className="pipeline-stage">
                  <div className="stage-icon-container">
                    <span className="material-symbols-outlined stage-icon">blur_on</span>
                  </div>
                  <h3 className="stage-title">FUZZ</h3>
                  <p className="stage-desc">Inject smart payloads adaptively</p>
                </div>
                
                <div className="pipeline-stage">
                  <div className="stage-icon-container">
                    <span className="material-symbols-outlined stage-icon">verified</span>
                  </div>
                  <h3 className="stage-title">VALIDATE</h3>
                  <p className="stage-desc">Confirm exploitability without impact</p>
                </div>
                
                <div className="pipeline-stage">
                  <div className="stage-icon-container">
                    <span className="material-symbols-outlined stage-icon">build</span>
                  </div>
                  <h3 className="stage-title">REMEDIATE</h3>
                  <p className="stage-desc">Actionable fixes and reproducer scripts</p>
                </div>
              </div>
            </div>
          </section>
        </div>
      </main>
    </div>
  );
}
