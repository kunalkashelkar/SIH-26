from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime

class ScanCreate(BaseModel):
    target_url: str
    scan_mode: str = "Standard"
    max_depth: int = 3
    max_requests: int = 10000

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
