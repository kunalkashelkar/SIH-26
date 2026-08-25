from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Float
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import sys
import os

# Ensure backend module can be found
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.database import Base

def generate_uuid():
    return str(uuid.uuid4())[:8]

class Project(Base):
    __tablename__ = "projects"
    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String, index=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    targets = relationship("Target", back_populates="project")

class Target(Base):
    __tablename__ = "targets"
    id = Column(String, primary_key=True, default=generate_uuid)
    project_id = Column(String, ForeignKey("projects.id"))
    url = Column(String, index=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    project = relationship("Project", back_populates="targets")
    scans = relationship("Scan", back_populates="target")

class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True, default=generate_uuid)
    target_id = Column(String, ForeignKey("targets.id"))
    status = Column(String, default="Initializing")
    progress = Column(Integer, default=0)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    
    target = relationship("Target", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")
    endpoints = relationship("Endpoint", back_populates="scan")

class Finding(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id"))
    type = Column(String)
    severity = Column(String)
    url = Column(String)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    scan = relationship("Scan", back_populates="findings")

class Endpoint(Base):
    __tablename__ = "endpoints"
    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id"))
    method = Column(String)
    url = Column(String)
    status_code = Column(Integer, nullable=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    scan = relationship("Scan", back_populates="endpoints")
