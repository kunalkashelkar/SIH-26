import React from 'react';
import './Documentation.css';

export default function Documentation() {
  return (
    <div className="docs-container">
      {/* Left Sidebar Navigation */}
      <div className="docs-sidebar">
        <h2 className="font-h3 text-h3 text-on-surface mb-1">Documentation</h2>
        <nav className="flex flex-col gap-1 w-full">
          <a className="docs-nav-link active" href="#">Getting Started</a>
          <div className="docs-nav-group">
            <a className="docs-nav-sublink" href="#">Installation</a>
            <a className="docs-nav-sublink" href="#">Quickstart Guide</a>
            <a className="docs-nav-sublink" href="#">Architecture Overview</a>
          </div>
          <a className="docs-nav-link" href="#">API Reference</a>
          <a className="docs-nav-link" href="#">Fuzzing Strategies</a>
          <a className="docs-nav-link" href="#">Remediation Workflows</a>
          <a className="docs-nav-link" href="#">Configuration</a>
        </nav>
      </div>

      {/* Main Content Area */}
      <div className="docs-main">
        <h1 className="docs-title">Getting Started with Sentinel</h1>
        <p className="docs-paragraph">
          Sentinel is a high-performance, distributed security scanning and fuzzing platform designed for continuous integration into developer workflows. This guide covers the foundational concepts and initial setup required to deploy Sentinel within your environment.
        </p>

        <div className="docs-alert">
          <div className="docs-alert-header">
            <span className="material-symbols-outlined text-primary text-[24px]">info</span>
            <h3 className="docs-alert-title">Prerequisites</h3>
          </div>
          <ul className="docs-list">
            <li>Docker v24.0 or higher</li>
            <li>Kubernetes cluster (v1.26+) for distributed deployments</li>
            <li>A valid Sentinel Enterprise License key</li>
          </ul>
        </div>

        <h2 className="docs-h2">Installation</h2>
        <p className="docs-paragraph" style={{marginBottom: '16px'}}>
          The fastest way to deploy Sentinel locally for testing is via the provided Docker Compose manifest. This will spin up the control plane, a single worker node, and the necessary data stores.
        </p>

        <div className="docs-code-block">
          <div className="docs-code-header">
            <span className="docs-code-lang">bash</span>
            <button className="docs-code-copy" onClick={() => navigator.clipboard.writeText('curl -sSL https://get.sentinel.dev/install.sh | bash')}>
              <span className="material-symbols-outlined text-[18px]">content_copy</span>
            </button>
          </div>
          <pre className="docs-code-content">
            <code><span style={{color: 'var(--color-tertiary)'}}>curl</span> -sSL https://get.sentinel.dev/install.sh | <span style={{color: 'var(--color-primary-container)'}}>bash</span></code>
          </pre>
        </div>

        <h2 className="docs-h2">Architecture</h2>
        <p className="docs-paragraph" style={{marginBottom: '16px'}}>
          Sentinel employs a hub-and-spoke architecture. The Control Plane manages scan scheduling, rule evaluation, and reporting, while distributed Worker Nodes execute the actual payload generation and target interaction.
        </p>

        <div className="docs-image-container group">
          <img 
            alt="Architecture Diagram" 
            src="https://lh3.googleusercontent.com/aida-public/AB6AXuBucFd7gSFYRAjkXwOPbupUgkquXA9z9zEhaXNTqpuisYseY5XNpNBccJIFFrTh3Egf3pjMcb8ip6YyvJM2-Pv2zdFz2AootP_ofITuIqoS90m--GLPEtH3sbGka_o05HDu_BDk1GeBEaOR-MnnQRFszvpvioM5N0WJekqEga0gJv-2DLP9wFHD-FkqmJ5SyNXWixdQ1rHu4-QUAb4de1AizuISkwPjenj_bMG1_A6sZLh29e1xsnaWgA" 
          />
        </div>

        <h3 className="docs-h3">Control Plane Component</h3>
        <p className="docs-paragraph" style={{marginBottom: '16px'}}>
          The control plane exposes a gRPC API for worker communication and a REST API for dashboard integration. Configuration is defined via YAML manifests.
        </p>

        <div className="docs-code-block">
          <div className="docs-code-header">
            <span className="docs-code-lang">sentinel-config.yaml</span>
          </div>
          <pre className="docs-code-content">
            <code><span style={{color: 'var(--color-primary-container)'}}>api_version:</span> v1alpha1
<span style={{color: 'var(--color-primary-container)'}}>kind:</span> ControlPlaneConfig
<span style={{color: 'var(--color-primary-container)'}}>metadata:</span>
  <span style={{color: 'var(--color-tertiary)'}}>name:</span> core-controller
<span style={{color: 'var(--color-primary-container)'}}>spec:</span>
  <span style={{color: 'var(--color-tertiary)'}}>listen_address:</span> <span style={{color: 'var(--color-error)'}}>"0.0.0.0:8080"</span>
  <span style={{color: 'var(--color-tertiary)'}}>tls_enabled:</span> <span style={{color: '#ffba42'}}>true</span>
  <span style={{color: 'var(--color-tertiary)'}}>data_retention_days:</span> 30</code>
          </pre>
        </div>

        <div className="docs-pagination">
          <button className="docs-btn-prev">
            <span className="material-symbols-outlined">arrow_back</span> Previous: Introduction
          </button>
          <button className="docs-btn-next">
            Next: API Reference <span className="material-symbols-outlined">arrow_forward</span>
          </button>
        </div>
      </div>

      {/* Right Table of Contents */}
      <div className="docs-toc">
        <span className="docs-toc-title">On this page</span>
        <a className="docs-toc-link" href="#">Prerequisites</a>
        <a className="docs-toc-link" href="#">Installation</a>
        <a className="docs-toc-link" href="#">Architecture</a>
        <a className="docs-toc-link" style={{paddingLeft: '12px'}} href="#">Control Plane Component</a>
      </div>
    </div>
  );
}
