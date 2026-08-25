from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime

class ScanCreate(BaseModel):
    target_url: str
    scan_mode: str = "Standard"
    max_depth: int = 3
    max_requests: int = 10000
    enable_subdomain_discovery: bool = False
    enable_directory_discovery: bool = False
    wordlist_limit: int = 100

class SubdomainResponse(BaseModel):
    id: str
    domain: str
    ip_address: Optional[str] = None
    is_alive: bool
    model_config = ConfigDict(from_attributes=True)

class ScanResponse(BaseModel):
    scan_id: str
    status: str

class ScanStatusResponse(BaseModel):
    status: str
    progress: int
    current_stage: str
    target_url: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)

class ParameterResponse(BaseModel):
    id: str
    endpoint_id: str
    name: str
    location: str
    value_type: str
    endpoint_method: str
    endpoint_path: str
    
class AttackSurfaceNodeResponse(BaseModel):
    id: str
    path: str
    method: str
    depth: int
    is_api: bool
    priority_score: int
    parameters: list[str]

class AttackSurfaceResponse(BaseModel):
    nodes: list[AttackSurfaceNodeResponse]
    total_endpoints: int
    total_apis: int
    model_config = ConfigDict(from_attributes=True)
