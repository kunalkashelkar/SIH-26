from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import List, Optional

class ProjectBase(BaseModel):
    name: str
    description: Optional[str] = None

class ProjectCreate(ProjectBase):
    pass

class ProjectResponse(ProjectBase):
    id: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class TargetBase(BaseModel):
    url: str
    description: Optional[str] = None
    project_id: str

class TargetCreate(TargetBase):
    pass

class TargetResponse(TargetBase):
    id: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class ScanBase(BaseModel):
    target_id: str

class ScanCreate(ScanBase):
    request_limit: int = 10000
    crawl_depth: int = 3

class ScanResponse(ScanBase):
    id: str
    status: str
    progress: int
    start_time: datetime
    end_time: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    type: str
    severity: str
    url: str
    description: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class EndpointResponse(BaseModel):
    id: str
    scan_id: str
    method: str
    url: str
    status_code: Optional[int]
    discovered_at: datetime
    model_config = ConfigDict(from_attributes=True)
