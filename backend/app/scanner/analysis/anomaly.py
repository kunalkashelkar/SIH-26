from pydantic import BaseModel
from typing import Optional, Any

class DifferentialSignals(BaseModel):
    status_code_changed: bool = False
    baseline_status: Optional[int] = None
    test_status: Optional[int] = None
    length_diff_bytes: int = 0
    length_diff_ratio: float = 0.0
    payload_reflected: bool = False
    sql_error_detected: bool = False
    server_error_triggered: bool = False
    content_type_changed: bool = False

class AnomalyReport(BaseModel):
    test_id: str
    scan_id: str
    endpoint_id: str
    parameter_id: Optional[str] = None
    parameter_name: str
    category: str
    payload: str
    anomaly: bool
    score: int  # 0 to 100
    signals: list[str] = []
    baseline_summary: str
    test_summary: str
    differential: Optional[DifferentialSignals] = None
