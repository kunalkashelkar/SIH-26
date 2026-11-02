from pydantic import BaseModel
from typing import Optional, Any

class FuzzTestResult(BaseModel):
    test_id: str
    scan_id: str
    endpoint_id: str
    parameter_id: Optional[str] = None
    parameter_name: str = ""
    category: str = "INPUT_VALIDATION"
    payload: str = ""
    status_code: Optional[int] = None
    response_time_ms: float = 0.0
    response_snippet: str = ""
    is_anomaly: bool = False
    anomaly_reason: Optional[str] = None
    error: Optional[str] = None
