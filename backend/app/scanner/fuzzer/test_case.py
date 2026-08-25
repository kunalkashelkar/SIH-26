from pydantic import BaseModel
from typing import Any, Optional

class TestCase(BaseModel):
    test_id: str
    scan_id: str
    endpoint_id: str
    parameter_id: Optional[str] = None
    parameter_name: str
    parameter_location: str  # query, body, path, header
    category: str            # SQLI, XSS, IDOR, AUTH_BYPASS, OPEN_REDIRECT, TYPE_CONFUSION
    target_url: str
    http_method: str
    payload: str
    expected_indicator: str
    description: str
