from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Float, Boolean, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from typing import Optional, List, Dict, Any
import uuid

from app.core.database import Base

def generate_uuid():
    return str(uuid.uuid4())

# ==============================================================================
# Discovery Classification Constants
# ==============================================================================
class DiscoveryStatus:
    # Phase 4 Canonical Classifications
    SOURCE_AND_RUNTIME_MATCH = "SOURCE_AND_RUNTIME_MATCH"
    SOURCE_ONLY = "SOURCE_ONLY"
    RUNTIME_ONLY = "RUNTIME_ONLY"
    SPECIFICATION_ONLY = "SPECIFICATION_ONLY"
    CANDIDATE = "CANDIDATE"
    RESTRICTED = "RESTRICTED"
    UNRESOLVED = "UNRESOLVED"

    # Compatibility Aliases
    SOURCE_DEFINED = "SOURCE_ONLY"
    RUNTIME_OBSERVED = "RUNTIME_ONLY"
    BOTH = "SOURCE_AND_RUNTIME_MATCH"
    FAILED = "FAILED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"

class RelationshipType:
    CORRELATED_WITH = "CORRELATED_WITH"
    CALLS_ENDPOINT = "CALLS_ENDPOINT"
    RENDERS_PAGE = "RENDERS_PAGE"
    DEFINES_OPERATION = "DEFINES_OPERATION"
    PROTECTED_BY = "PROTECTED_BY"
    SUBMITS_TO = "SUBMITS_TO"
    VALIDATES_WITH = "VALIDATES_WITH"
    CONTAINS = "CONTAINS"


class DiscoverySource:
    STATIC_HTML = "STATIC_HTML"
    SITEMAP = "SITEMAP"
    PLAYWRIGHT = "PLAYWRIGHT"
    NETWORK_INTERCEPTION = "NETWORK_INTERCEPTION"
    JAVASCRIPT_ANALYSIS = "JAVASCRIPT_ANALYSIS"
    SOURCE_CODE_ANALYSIS = "SOURCE_CODE_ANALYSIS"
    OPENAPI = "OPENAPI"
    GRAPHQL_SCHEMA = "GRAPHQL_SCHEMA"
    HAR_IMPORT = "HAR_IMPORT"
    MANUAL_IMPORT = "MANUAL_IMPORT"

class AssetType:
    WEBSITE_PAGE = "WEBSITE_PAGE"
    FRONTEND_ROUTE = "FRONTEND_ROUTE"
    BACKEND_API_OPERATION = "BACKEND_API_OPERATION"
    API_OPERATION = "BACKEND_API_OPERATION"
    HTTP_ENDPOINT = "HTTP_ENDPOINT"
    GRAPHQL_OPERATION = "GRAPHQL_OPERATION"
    WEBSOCKET_ENDPOINT = "WEBSOCKET_ENDPOINT"
    FORM = "FORM"
    PARAMETER = "PARAMETER"
    JAVASCRIPT_RESOURCE = "JAVASCRIPT_RESOURCE"
    SOURCE_FILE = "SOURCE_FILE"
    CONTROLLER = "CONTROLLER"
    MIDDLEWARE = "MIDDLEWARE"
    AUTHENTICATION_RULE = "AUTHENTICATION_RULE"
    API_SPECIFICATION = "API_SPECIFICATION"

class ScanMode:
    WEBSITE_ONLY = "WEBSITE_ONLY"
    GITHUB_ONLY = "GITHUB_ONLY"
    REPOSITORY_ONLY = "GITHUB_ONLY"
    HYBRID = "HYBRID"

# ==============================================================================
# 1. Target Profiles
# ==============================================================================

class WebsiteProfile(Base):
    __tablename__ = "website_profiles"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    base_url = Column(String, nullable=False, index=True)
    host = Column(String, nullable=True, index=True)
    title = Column(String, nullable=True)
    tech_stack = Column(JSON, default=list)
    sitemap_url = Column(String, nullable=True)
    robots_txt_present = Column(Boolean, default=False)
    security_headers = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="website_profile")

class RepositoryProfile(Base):
    __tablename__ = "repository_profiles"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    repo_url = Column(String, nullable=False, index=True)
    branch = Column(String, default="main")
    commit_sha = Column(String, nullable=True)
    detected_languages = Column(JSON, default=list)
    detected_frameworks = Column(JSON, default=list)
    total_files_analyzed = Column(Integer, default=0)
    total_routes_detected = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="repository_profile")

    @property
    def total_routes_discovered(self) -> int:
        return self.total_routes_detected or 0

    @total_routes_discovered.setter
    def total_routes_discovered(self, val: int):
        self.total_routes_detected = val

# ==============================================================================
# 2. Master Discovered Assets
# ==============================================================================

class DiscoveredAsset(Base):
    __tablename__ = "discovered_assets"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_type = Column(String, nullable=False, index=True)
    identifier = Column(String, nullable=False, index=True)
    name = Column(String, nullable=True)
    path = Column(String, nullable=True, index=True)
    url = Column(String, nullable=True, index=True)
    method = Column(String, nullable=True, default="GET")
    discovery_status = Column(String, default=DiscoveryStatus.CANDIDATE, index=True)
    confidence = Column(Float, default=1.0)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    scan = relationship("Scan", back_populates="discovered_assets")
    source_evidences = relationship("SourceEvidence", back_populates="asset", cascade="all, delete-orphan")
    runtime_evidences = relationship("RuntimeEvidence", back_populates="asset", cascade="all, delete-orphan")
    parameters = relationship("EndpointParameter", back_populates="asset", cascade="all, delete-orphan")
    
    outgoing_relations = relationship(
        "AssetRelationship",
        foreign_keys="AssetRelationship.source_asset_id",
        back_populates="source_asset",
        cascade="all, delete-orphan"
    )
    incoming_relations = relationship(
        "AssetRelationship",
        foreign_keys="AssetRelationship.target_asset_id",
        back_populates="target_asset",
        cascade="all, delete-orphan"
    )

# ==============================================================================
# 3. Typed Discovery Asset Tables
# ==============================================================================

class DiscoveredPage(Base):
    __tablename__ = "discovered_pages"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(String, ForeignKey("discovered_assets.id", ondelete="CASCADE"), nullable=True, index=True)
    url = Column(String, nullable=False, index=True)
    title = Column(String, nullable=True)
    status_code = Column(Integer, nullable=True)
    content_type = Column(String, nullable=True)
    response_size = Column(Integer, default=0)
    dom_elements_count = Column(Integer, default=0)
    forms_count = Column(Integer, default=0)
    links_count = Column(Integer, default=0)
    has_auth_form = Column(Boolean, default=False)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class DiscoveredRoute(Base):
    __tablename__ = "discovered_routes"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(String, ForeignKey("discovered_assets.id", ondelete="CASCADE"), nullable=True, index=True)
    route_pattern = Column(String, nullable=False, index=True)
    method = Column(String, nullable=False, default="GET")
    route_type = Column(String, default="BACKEND", index=True)  # FRONTEND, BACKEND
    framework = Column(String, nullable=True, index=True)       # FASTAPI, FLASK, DJANGO, EXPRESS, NEXTJS
    source_file = Column(String, nullable=True)
    source_line = Column(Integer, nullable=True)
    handler_name = Column(String, nullable=True)
    auth_required = Column(Boolean, default=False)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class DiscoveredEndpoint(Base):
    __tablename__ = "discovered_endpoints"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(String, ForeignKey("discovered_assets.id", ondelete="CASCADE"), nullable=True, index=True)
    url = Column(String, nullable=False, index=True)
    path = Column(String, nullable=False, index=True)
    method = Column(String, nullable=False, default="GET")
    status_code = Column(Integer, nullable=True)
    content_type = Column(String, nullable=True)
    is_api = Column(Boolean, default=False)
    depth = Column(Integer, default=0)
    discovered_from = Column(String, nullable=True)
    discovery_status = Column(String, default=DiscoveryStatus.CANDIDATE, index=True)
    priority_score = Column(Float, default=0.0)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    parameters = relationship("EndpointParameter", back_populates="endpoint", cascade="all, delete-orphan")

class EndpointParameter(Base):
    __tablename__ = "endpoint_parameters"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    endpoint_id = Column(String, ForeignKey("discovered_endpoints.id", ondelete="CASCADE"), nullable=True, index=True)
    asset_id = Column(String, ForeignKey("discovered_assets.id", ondelete="CASCADE"), nullable=True, index=True)
    name = Column(String, nullable=False, index=True)
    location = Column(String, nullable=False, default="query")  # query, body, path, header, cookie
    value_type = Column(String, default="string")
    is_required = Column(Boolean, default=False)
    example_value = Column(String, nullable=True)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    asset = relationship("DiscoveredAsset", back_populates="parameters")
    endpoint = relationship("DiscoveredEndpoint", back_populates="parameters")

class DiscoveredForm(Base):
    __tablename__ = "discovered_forms"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(String, ForeignKey("discovered_assets.id", ondelete="CASCADE"), nullable=True, index=True)
    page_url = Column(String, nullable=False, index=True)
    action = Column(String, nullable=True)
    method = Column(String, default="POST")
    form_type = Column(String, default="GENERAL", index=True)   # LOGIN, REGISTRATION, SEARCH, DATA_INPUT, GENERAL
    inputs_count = Column(Integer, default=0)
    inputs_schema = Column(JSON, default=list)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class SourceFile(Base):
    __tablename__ = "source_files"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    file_path = Column(String, nullable=False, index=True)
    language = Column(String, nullable=True, index=True)        # PYTHON, TYPESCRIPT, JAVASCRIPT, JSON, YAML
    file_type = Column(String, nullable=True, index=True)       # CONTROLLER, ROUTE, MIDDLEWARE, MODEL, SCHEMA
    lines_count = Column(Integer, default=0)
    imports = Column(JSON, default=list)
    exports = Column(JSON, default=list)
    raw_sha = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    evidences = relationship("SourceEvidence", back_populates="source_file")

# ==============================================================================
# 4. Evidence Records
# ==============================================================================

class SourceEvidence(Base):
    __tablename__ = "source_evidence"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(String, ForeignKey("discovered_assets.id", ondelete="CASCADE"), nullable=False, index=True)
    source_file_id = Column(String, ForeignKey("source_files.id", ondelete="SET NULL"), nullable=True, index=True)
    discovery_source = Column(String, default=DiscoverySource.SOURCE_CODE_ANALYSIS, index=True)
    file_path = Column(String, nullable=False)
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    snippet = Column(Text, nullable=True)
    ast_node_type = Column(String, nullable=True)
    rule_name = Column(String, nullable=True)
    confidence = Column(Float, default=1.0)
    verification_status = Column(String, default=DiscoveryStatus.SOURCE_DEFINED)
    evidence_reference = Column(String, nullable=True)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    asset = relationship("DiscoveredAsset", back_populates="source_evidences")
    source_file = relationship("SourceFile", back_populates="evidences")

class RuntimeEvidence(Base):
    __tablename__ = "runtime_evidence"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(String, ForeignKey("discovered_assets.id", ondelete="CASCADE"), nullable=False, index=True)
    discovery_source = Column(String, default=DiscoverySource.STATIC_HTML, index=True)
    observation_type = Column(String, default="HTTP_REQUEST", index=True) # PAGE_LOAD, HTTP_REQUEST, DOM_MUTATION
    url = Column(String, nullable=False, index=True)
    method = Column(String, default="GET")
    request_headers = Column(JSON, default=dict)
    request_body = Column(Text, nullable=True)
    response_status = Column(Integer, nullable=True)
    response_headers = Column(JSON, default=dict)
    response_body_sample = Column(Text, nullable=True)
    response_time_ms = Column(Float, default=0.0)
    confidence = Column(Float, default=1.0)
    verification_status = Column(String, default=DiscoveryStatus.RUNTIME_OBSERVED)
    evidence_reference = Column(String, nullable=True)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    asset = relationship("DiscoveredAsset", back_populates="runtime_evidences")

# ==============================================================================
# 5. Security & Lifecycle Records
# ==============================================================================

class AuthenticationObservation(Base):
    __tablename__ = "authentication_observations"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    auth_type = Column(String, nullable=False, index=True)     # BEARER_JWT, COOKIE_SESSION, OAUTH, BASIC, NONE
    login_url = Column(String, nullable=True)
    token_location = Column(String, nullable=True)
    session_cookie_name = Column(String, nullable=True)
    roles_detected = Column(JSON, default=list)
    is_authenticated = Column(Boolean, default=False)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    @property
    def source_file(self) -> Optional[str]:
        if isinstance(self.metadata_json, dict):
            return self.metadata_json.get("source_file")
        return None

    @property
    def source_line(self) -> Optional[int]:
        if isinstance(self.metadata_json, dict):
            return self.metadata_json.get("source_line")
        return None

class DiscoveryEvent(Base):
    __tablename__ = "discovery_events"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String, nullable=False, index=True)    # PHASE_START, PHASE_COMPLETE, ASSET_DISCOVERED, CORRELATION_MATCH
    phase = Column(String, nullable=False, index=True)
    message = Column(Text, nullable=False)
    details = Column(JSON, default=dict)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="discovery_events")

class DiscoveryError(Base):
    __tablename__ = "discovery_errors"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    component = Column(String, nullable=False, index=True)
    error_type = Column(String, nullable=False, index=True)
    message = Column(Text, nullable=False)
    stack_trace = Column(Text, nullable=True)
    target_url = Column(String, nullable=True)
    source_file = Column(String, nullable=True)
    retryable = Column(Boolean, default=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="discovery_errors")

class AssetRelationship(Base):
    __tablename__ = "asset_relationships"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    source_asset_id = Column(String, ForeignKey("discovered_assets.id", ondelete="CASCADE"), nullable=False, index=True)
    target_asset_id = Column(String, ForeignKey("discovered_assets.id", ondelete="CASCADE"), nullable=False, index=True)
    relationship_type = Column(String, nullable=False, index=True) # CONTAINS, CALLS, RENDERS, AUTHENTICATES, DEPENDS_ON
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    source_asset = relationship("DiscoveredAsset", foreign_keys=[source_asset_id], back_populates="outgoing_relations")
    target_asset = relationship("DiscoveredAsset", foreign_keys=[target_asset_id], back_populates="incoming_relations")


class StageStatus:
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    BLOCKED = "BLOCKED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    CANCELLED = "CANCELLED"


class FailureCategory:
    TRANSIENT = "TRANSIENT"
    PERMANENT = "PERMANENT"
    ENVIRONMENTAL = "ENVIRONMENTAL"
    PARTIAL = "PARTIAL"
    CANCELLED = "CANCELLED"


class ScanStage(Base):
    __tablename__ = "scan_stages"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    stage_name = Column(String, nullable=False, index=True)
    stage_status = Column(String, default="PENDING", index=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    duration = Column(Float, default=0.0)
    input_count = Column(Integer, default=0)
    processed_count = Column(Integer, default=0)
    successful_count = Column(Integer, default=0)
    failed_count = Column(Integer, default=0)
    skipped_count = Column(Integer, default=0)
    output_count = Column(Integer, default=0)
    retry_count = Column(Integer, default=0)
    error_code = Column(String, nullable=True)
    error_message = Column(Text, nullable=True)
    failure_category = Column(String, nullable=True)
    execution_metadata = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="stages")
    attempts = relationship("StageAttempt", back_populates="stage", cascade="all, delete-orphan")


class StageAttempt(Base):
    __tablename__ = "stage_attempts"
    id = Column(String, primary_key=True, default=generate_uuid)
    stage_id = Column(String, ForeignKey("scan_stages.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    attempt_number = Column(Integer, default=1)
    status = Column(String, nullable=False) # RUNNING, COMPLETED, FAILED
    error_message = Column(Text, nullable=True)
    failure_category = Column(String, nullable=True)
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    duration = Column(Float, default=0.0)

    stage = relationship("ScanStage", back_populates="attempts")
