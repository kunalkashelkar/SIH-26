import React from 'react';
import './Documentation.css';

export default function Documentation() {
  return (
    <div className="docs-container">
      {/* Left Sidebar Navigation */}
      <div className="docs-sidebar">
        <h2 className="font-h3 text-h3 text-on-surface mb-1">Architecture & Guide</h2>
        <nav className="flex flex-col gap-1 w-full">
          <a className="docs-nav-link active" href="#overview">System Overview</a>
          <div className="docs-nav-group">
            <a className="docs-nav-sublink" href="#pipeline">End-to-End Pipeline</a>
            <a className="docs-nav-sublink" href="#discovery">Discovery & Fuzzing</a>
            <a className="docs-nav-sublink" href="#ml">Phase 14 ML Engine</a>
            <a className="docs-nav-sublink" href="#graph">Attack Graph Topology</a>
          </div>
          <a className="docs-nav-link" href="#features">19 Raw Features</a>
          <a className="docs-nav-link" href="#shap">SHAP Explainability</a>
          <a className="docs-nav-link" href="#api">FastAPI Contracts</a>
        </nav>
      </div>

      {/* Main Content Area */}
      <div className="docs-main">
        <h1 className="docs-title" id="overview">Sentinel Platform Architecture</h1>
        <p className="docs-paragraph">
          Sentinel is an autonomous security intelligence and vulnerability fuzzing platform. It unifies active web crawling, differential response probing, targeted re-testing, NetworkX graph analysis, and XGBoost machine learning classification into a live PostgreSQL-backed security pipeline.
        </p>

        {/* Pipeline Section */}
        <h2 className="docs-h2" id="pipeline">12-Stage Data Flow Pipeline</h2>
        <div style={{
          padding: '16px',
          background: 'rgba(0,0,0,0.3)',
          border: '1px solid var(--color-outline-variant)',
          borderRadius: '8px',
          fontFamily: 'var(--font-mono)',
          fontSize: '12px',
          color: 'var(--color-primary)',
          lineHeight: '1.8',
          marginBottom: '24px'
        }}>
          Target URL<br/>
          &nbsp;&nbsp;↓ [HTML Crawler & OpenAPI Parser]<br/>
          Discovery (Endpoints & Parameters)<br/>
          &nbsp;&nbsp;↓ [Adaptive Payload Engine]<br/>
          Async HTTP Fuzzing Probes<br/>
          &nbsp;&nbsp;↓ [Differential Comparator]<br/>
          Response Anomaly Scoring<br/>
          &nbsp;&nbsp;↓ [Targeted Validation Probes]<br/>
          Confirmed Vulnerabilities & Evidence<br/>
          &nbsp;&nbsp;↓ [19-Feature Vector Extraction]<br/>
          ColumnTransformer Preprocessor (19 → 27 Features)<br/>
          &nbsp;&nbsp;↓ [Tuned XGBoost Binary Classifier]<br/>
          ML Vulnerability Classification & SHAP Weighting<br/>
          &nbsp;&nbsp;↓ [Rule-Based Triage + CVSS v3.1]<br/>
          PostgreSQL Storage (`findings`, `evidence`, `retests`)<br/>
          &nbsp;&nbsp;↓ [FastAPI REST APIs]<br/>
          React Visualization & Interactive Hierarchical Graph
        </div>

        {/* Machine Learning Section */}
        <h2 className="docs-h2" id="ml">Phase 14 XGBoost ML Intelligence</h2>
        <p className="docs-paragraph">
          The ML vulnerability detection engine operates on 19 raw features extracted from endpoint attributes and fuzzer telemetry. The repaired <code>preprocessor.pkl</code> transforms categorical inputs (HTTP method and endpoint type) into one-hot encodings and normalizes numerical features into a 27-dimensional orthogonal vector.
        </p>

        <div className="docs-alert">
          <div className="docs-alert-header">
            <span className="material-symbols-outlined text-primary text-[24px]">psychology</span>
            <h3 className="docs-alert-title">Model Performance Benchmarks</h3>
          </div>
          <ul className="docs-list">
            <li><strong>Model Architecture:</strong> XGBoost Gradient Boosted Trees (Binary Classifier)</li>
            <li><strong>Validation ROC-AUC:</strong> 0.9960 (Tuned on 2,100 discovery observations)</li>
            <li><strong>Test Accuracy:</strong> 95.11% (Precision: 95.93%, Recall: 94.22%, F1: 95.07%)</li>
            <li><strong>Inference Guarantee:</strong> Deterministic $19 \to 27$ feature transformation with $[0.0, 1.0]$ probability bounds.</li>
          </ul>
        </div>

        {/* Features Table */}
        <h2 className="docs-h2" id="features">19 Raw ML Features Specification</h2>
        <div style={{overflowX: 'auto', marginBottom: '24px'}}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Feature Name</th>
                <th>Type</th>
                <th>Source Pipeline Stage</th>
              </tr>
            </thead>
            <tbody>
              <tr><td className="font-mono">http_method</td><td>Categorical</td><td>Endpoint Discovery (Crawler)</td></tr>
              <tr><td className="font-mono">endpoint_depth</td><td>Numerical</td><td>URI Path Tokenizer</td></tr>
              <tr><td className="font-mono">endpoint_type</td><td>Categorical</td><td>OpenAPI / Path Classifier</td></tr>
              <tr><td className="font-mono">parameter_count</td><td>Numerical</td><td>Discovered Input Elements</td></tr>
              <tr><td className="font-mono">query_parameter_count</td><td>Numerical</td><td>Query String Extractor</td></tr>
              <tr><td className="font-mono">body_parameter_count</td><td>Numerical</td><td>Form / JSON Body Inspector</td></tr>
              <tr><td className="font-mono">authentication_required</td><td>Binary (0/1)</td><td>HTTP Status Code Boundary (401/403)</td></tr>
              <tr><td className="font-mono">external_exposure</td><td>Binary (0/1)</td><td>DNS Host Heuristic (Public vs Local)</td></tr>
              <tr><td className="font-mono">response_status</td><td>Numerical</td><td>Probe HTTP Response Code</td></tr>
              <tr><td className="font-mono">response_size</td><td>Numerical</td><td>Probe Response Body Length</td></tr>
              <tr><td className="font-mono">response_time</td><td>Numerical</td><td>HTTP Round-Trip Latency (seconds)</td></tr>
              <tr><td className="font-mono">response_anomaly_score</td><td>Numerical</td><td>Differential Comparator Divergence</td></tr>
              <tr><td className="font-mono">graph_degree</td><td>Numerical</td><td>NetworkX Node Degree</td></tr>
              <tr><td className="font-mono">related_endpoint_count</td><td>Numerical</td><td>Parent Domain Sibling Count</td></tr>
              <tr><td className="font-mono">api_relationship_count</td><td>Numerical</td><td>Connected API Schema Group Count</td></tr>
              <tr><td className="font-mono">subdomain_relationship</td><td>Binary (0/1)</td><td>Subdomain Catalog Match</td></tr>
              <tr><td className="font-mono">vhost_relationship</td><td>Binary (0/1)</td><td>Virtual Host Catalog Match</td></tr>
              <tr><td className="font-mono">previous_vulnerability_evidence</td><td>Numerical</td><td>Historical Confirmed Findings</td></tr>
              <tr><td className="font-mono">fuzzing_history</td><td>Numerical</td><td>Historical Probe Attempts Count</td></tr>
            </tbody>
          </table>
        </div>

        {/* SHAP Explainability */}
        <h2 className="docs-h2" id="shap">SHAP Decision Weighting</h2>
        <p className="docs-paragraph">
          XGBoost feature gain importances reveal that confirmed historical evidence (Gain: 26.82), external attack surface exposure (Gain: 7.48), response anomaly divergence (Gain: 4.32), and user-controlled parameter volume (Gain: 4.05) are the dominant drivers of vulnerability classification.
        </p>

      </div>

      {/* Right Table of Contents */}
      <div className="docs-toc">
        <span className="docs-toc-title">On this page</span>
        <a className="docs-toc-link" href="#overview">System Overview</a>
        <a className="docs-toc-link" href="#pipeline">12-Stage Pipeline</a>
        <a className="docs-toc-link" href="#ml">ML Intelligence</a>
        <a className="docs-toc-link" href="#features">19 Raw Features</a>
        <a className="docs-toc-link" href="#shap">SHAP Weighting</a>
      </div>
    </div>
  );
}

