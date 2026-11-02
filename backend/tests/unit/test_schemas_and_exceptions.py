import pytest
from app.core.exceptions import (
    AppException, NotFoundException, ValidationException,
    ForbiddenException, format_error_response
)
from app.schemas.common import StandardResponse, PaginationMeta, PaginatedData
from app.schemas.scans import FindingResponse
from app.models.models import Parameter

def test_app_exceptions_and_formatting():
    exc = NotFoundException("Scan", "1234")
    assert exc.status_code == 404
    assert exc.code == "SCAN_NOT_FOUND"

    payload = format_error_response(
        code=exc.code,
        message=exc.message,
        request_id="req-999",
        details=exc.details
    )
    assert payload["success"] is False
    assert payload["data"] is None
    assert payload["error"]["code"] == "SCAN_NOT_FOUND"
    assert payload["error"]["request_id"] == "req-999"

def test_finding_response_parameter_converter():
    # If parameter is a Parameter ORM object
    param_obj = Parameter(id="p-1", endpoint_id="ep-1", name="search_query")
    raw_dict = {
        "id": "f-1",
        "scan_id": "s-1",
        "vulnerability_type": "SQL Injection",
        "severity": "CRITICAL",
        "status": "verified",
        "parameter": param_obj
    }
    resp = FindingResponse.model_validate(raw_dict)
    assert resp.parameter == "search_query"

    # If parameter is already a string
    raw_dict_str = {
        "id": "f-2",
        "scan_id": "s-1",
        "vulnerability_type": "XSS",
        "severity": "HIGH",
        "status": "open",
        "parameter": "user_id"
    }
    resp_str = FindingResponse.model_validate(raw_dict_str)
    assert resp_str.parameter == "user_id"

def test_pagination_meta_validation():
    meta = PaginationMeta(page=2, limit=20, total=45, total_pages=3)
    assert meta.page == 2
    assert meta.total_pages == 3
