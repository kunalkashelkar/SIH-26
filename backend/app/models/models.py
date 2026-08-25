from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Float, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid

from app.core.database import Base

def generate_uuid():
    return str(uuid.uuid4())

class Target(Base):
    __tablename__ = "targets"
    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String, nullable=False, index=True)
    base_url = Column(String, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")

class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True, default=generate_uuid)
    target_id = Column(String, ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String, default="pending", index=True)
    scan_mode = Column(String)
    current_stage = Column(String, default="INITIALIZING", index=True)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    progress = Column(Integer, default=0)
    error_message = Column(Text)
    
    target = relationship("Target", back_populates="scans")
    endpoints = relationship("Endpoint", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    subdomains = relationship("Subdomain", back_populates="scan", cascade="all, delete-orphan")

class Endpoint(Base):
    __tablename__ = "endpoints"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(String, nullable=False, index=True)
    path = Column(String, nullable=False)
    method = Column(String, nullable=False)
    status_code = Column(Integer)
    content_type = Column(String)
    depth = Column(Integer, default=0)
    discovered_from = Column(String)
    is_api = Column(Boolean, default=False)
    priority_score = Column(Float, default=0.0)
    
    scan = relationship("Scan", back_populates="endpoints")
    parameters = relationship("Parameter", back_populates="endpoint", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="endpoint")

class Parameter(Base):
    __tablename__ = "parameters"
    id = Column(String, primary_key=True, default=generate_uuid)
    endpoint_id = Column(String, ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String, nullable=False, index=True)
    location = Column(String, nullable=False) # e.g. query, body, header
    value_type = Column(String)
    
    endpoint = relationship("Endpoint", back_populates="parameters")
    findings = relationship("Finding", back_populates="parameter")

class Finding(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    endpoint_id = Column(String, ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True, index=True)
    parameter_id = Column(String, ForeignKey("parameters.id", ondelete="SET NULL"), nullable=True, index=True)
    vulnerability_type = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False, index=True)
    confidence = Column(String)
    status = Column(String, default="open", index=True)
    description = Column(Text)
    impact = Column(Text)
    cwe = Column(String)
    owasp_category = Column(String)
    remediation = Column(Text)
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
    evidence_type = Column(String)
    baseline_summary = Column(Text)
    test_summary = Column(Text)
    analysis = Column(Text)
    confidence = Column(String)
    
    finding = relationship("Finding", back_populates="evidence")

class Retest(Base):
    __tablename__ = "retests"
    id = Column(String, primary_key=True, default=generate_uuid)
    finding_id = Column(String, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String, default="pending", index=True)
    result = Column(String)
    executed_at = Column(DateTime(timezone=True))
    
    finding = relationship("Finding", back_populates="retests")

class Subdomain(Base):
    __tablename__ = "subdomains"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    domain = Column(String, nullable=False, index=True)
    ip_address = Column(String)
    is_alive = Column(Boolean, default=False)
    
    scan = relationship("Scan", back_populates="subdomains")
