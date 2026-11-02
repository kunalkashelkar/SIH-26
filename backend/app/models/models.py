from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Float, Boolean, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid

from app.core.database import Base

def generate_uuid():
    return str(uuid.uuid4())

class Project(Base):
    __tablename__ = "projects"
    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String, nullable=False, index=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    targets = relationship("Target", back_populates="project", cascade="all, delete-orphan")

class Target(Base):
    __tablename__ = "targets"
    id = Column(String, primary_key=True, default=generate_uuid)
    project_id = Column(String, ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True)
    name = Column(String, nullable=False, index=True)
    base_url = Column(String, nullable=False, index=True)
    repo_url = Column(String, nullable=True, index=True)
    repo_branch = Column(String, nullable=True, default="main")
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    project = relationship("Project", back_populates="targets")
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")

class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, nullable=True, index=True)
    target_id = Column(String, ForeignKey("targets.id", ondelete="CASCADE"), nullable=True, index=True)
    status = Column(String, default="QUEUED", index=True)
    scan_mode = Column(String, default="Standard")
    discovery_mode = Column(String, default="WEBSITE_ONLY", index=True)
    website_url = Column(String, nullable=True, index=True)
    repository_url = Column(String, nullable=True, index=True)
    repository_branch = Column(String, nullable=True, default="main")
    repository_commit_sha = Column(String, nullable=True)
    current_stage = Column(String, default="INITIALIZING", index=True)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    progress = Column(Integer, default=0)
    configuration = Column(JSON, nullable=True, default=dict)
    error_message = Column(Text, nullable=True)
    
    target = relationship("Target", back_populates="scans")
    endpoints = relationship("Endpoint", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    subdomains = relationship("Subdomain", back_populates="scan", cascade="all, delete-orphan")
    virtual_hosts = relationship("VirtualHost", back_populates="scan", cascade="all, delete-orphan")
    fuzz_results = relationship("FuzzResult", back_populates="scan", cascade="all, delete-orphan")
    logs = relationship("ScanLog", back_populates="scan", cascade="all, delete-orphan")

    # Unified Discovery Relationships
    website_profile = relationship("WebsiteProfile", uselist=False, back_populates="scan", cascade="all, delete-orphan")
    repository_profile = relationship("RepositoryProfile", uselist=False, back_populates="scan", cascade="all, delete-orphan")
    discovered_assets = relationship("DiscoveredAsset", back_populates="scan", cascade="all, delete-orphan")
    discovery_events = relationship("DiscoveryEvent", back_populates="scan", cascade="all, delete-orphan")
    discovery_errors = relationship("DiscoveryError", back_populates="scan", cascade="all, delete-orphan")
    stages = relationship("ScanStage", back_populates="scan", cascade="all, delete-orphan")

class Endpoint(Base):
    __tablename__ = "endpoints"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(String, nullable=False, index=True)
    path = Column(String, nullable=False, index=True)
    method = Column(String, nullable=False, default="GET")
    status_code = Column(Integer, nullable=True)
    content_type = Column(String, nullable=True)
    depth = Column(Integer, default=0)
    discovered_from = Column(String, nullable=True)
    is_api = Column(Boolean, default=False)
    priority_score = Column(Float, default=0.0)
    
    scan = relationship("Scan", back_populates="endpoints")
    parameters = relationship("Parameter", back_populates="endpoint", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="endpoint")
    fuzz_results = relationship("FuzzResult", back_populates="endpoint")

class Parameter(Base):
    __tablename__ = "parameters"
    id = Column(String, primary_key=True, default=generate_uuid)
    endpoint_id = Column(String, ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String, nullable=False, index=True)
    location = Column(String, nullable=False, default="query")  # query, body, header, path
    value_type = Column(String, nullable=True, default="string")
    
    endpoint = relationship("Endpoint", back_populates="parameters")
    findings = relationship("Finding", back_populates="parameter")
    fuzz_results = relationship("FuzzResult", back_populates="parameter")

class Finding(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    endpoint_id = Column(String, ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True, index=True)
    parameter_id = Column(String, ForeignKey("parameters.id", ondelete="SET NULL"), nullable=True, index=True)
    asset_id = Column(String, nullable=True, index=True)
    title = Column(String, nullable=True, index=True)
    vulnerability_type = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence = Column(String, default="90%")
    priority = Column(String, default="P2", index=True)
    status = Column(String, default="open", index=True)  # open, verified, likely, unconfirmed, false_positive, closed
    description = Column(Text, nullable=True)
    technical_details = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    affected_url = Column(String, nullable=True)
    affected_endpoint = Column(String, nullable=True)
    http_method = Column(String, nullable=True)
    parameter_name = Column(String, nullable=True)
    source_file = Column(String, nullable=True)
    source_line_start = Column(Integer, nullable=True)
    source_line_end = Column(Integer, nullable=True)
    cwe = Column(String, nullable=True)
    owasp_category = Column(String, nullable=True)
    detection_method = Column(String, nullable=True) # STATIC_AST, DYNAMIC_FUZZING, RUNTIME_INTERCEPTION
    validation_method = Column(String, nullable=True)
    first_detected_at = Column(DateTime(timezone=True), server_default=func.now())
    last_updated_at = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    scan = relationship("Scan", back_populates="findings")
    endpoint = relationship("Endpoint", back_populates="findings")
    parameter = relationship("Parameter", back_populates="findings")
    evidence = relationship("Evidence", back_populates="finding", cascade="all, delete-orphan")
    retests = relationship("Retest", back_populates="finding", cascade="all, delete-orphan")

class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(String, primary_key=True, default=generate_uuid)
    finding_id = Column(String, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_type = Column(String, nullable=True)
    baseline_summary = Column(Text, nullable=True)
    test_summary = Column(Text, nullable=True)
    analysis = Column(Text, nullable=True)
    confidence = Column(String, nullable=True, default="HIGH")
    
    finding = relationship("Finding", back_populates="evidence")

class Retest(Base):
    __tablename__ = "retests"
    id = Column(String, primary_key=True, default=generate_uuid)
    finding_id = Column(String, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String, default="completed", index=True)
    result = Column(String, default="VULNERABLE")
    executed_at = Column(DateTime(timezone=True), server_default=func.now())
    
    finding = relationship("Finding", back_populates="retests")

class Subdomain(Base):
    __tablename__ = "subdomains"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    domain = Column(String, nullable=False, index=True)
    ip_address = Column(String, nullable=True)
    is_alive = Column(Boolean, default=False)
    
    scan = relationship("Scan", back_populates="subdomains")

class VirtualHost(Base):
    __tablename__ = "virtual_hosts"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    host = Column(String, nullable=False, index=True)
    ip_address = Column(String, nullable=True)
    status_code = Column(Integer, nullable=True)
    is_active = Column(Boolean, default=True)
    
    scan = relationship("Scan", back_populates="virtual_hosts")

class PayloadItem(Base):
    __tablename__ = "payload_items"
    id = Column(String, primary_key=True, default=generate_uuid)
    category = Column(String, nullable=False, index=True)  # SQLI, XSS, IDOR, etc.
    payload = Column(Text, nullable=False)
    indicator = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    is_custom = Column(Boolean, default=False)
    usage_count = Column(Integer, default=0)
    success_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class FuzzResult(Base):
    __tablename__ = "fuzz_results"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    endpoint_id = Column(String, ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True, index=True)
    parameter_id = Column(String, ForeignKey("parameters.id", ondelete="SET NULL"), nullable=True, index=True)
    test_id = Column(String, nullable=True)
    category = Column(String, nullable=False, index=True)
    payload = Column(Text, nullable=False)
    status_code = Column(Integer, nullable=True)
    response_time_ms = Column(Float, default=0.0)
    anomaly_detected = Column(Boolean, default=False, index=True)
    details = Column(Text, nullable=True)
    executed_at = Column(DateTime(timezone=True), server_default=func.now())
    
    scan = relationship("Scan", back_populates="fuzz_results")
    endpoint = relationship("Endpoint", back_populates="fuzz_results")
    parameter = relationship("Parameter", back_populates="fuzz_results")

class ScanLog(Base):
    __tablename__ = "scan_logs"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    level = Column(String, default="INFO")  # INFO, WARN, CRITICAL, SUCCESS
    message = Column(Text, nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    
    scan = relationship("Scan", back_populates="logs")

# Register unified discovery models with Base metadata
from app.models.discovery import (
    DiscoveryStatus, DiscoverySource, AssetType, ScanMode,
    WebsiteProfile, RepositoryProfile, DiscoveredAsset,
    DiscoveredPage, DiscoveredRoute, DiscoveredEndpoint as HybridDiscoveredEndpoint,
    EndpointParameter, DiscoveredForm, SourceFile,
    SourceEvidence, RuntimeEvidence, AuthenticationObservation,
    DiscoveryEvent, DiscoveryError, AssetRelationship
)
