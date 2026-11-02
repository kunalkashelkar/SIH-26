"""
Source code discovery data models and parser abstractions.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class SourceParameter:
    name: str
    location: str = "query"  # query, body, path, header
    value_type: str = "string"
    is_required: bool = False
    default_value: Optional[str] = None
    validation_rules: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SourceAuthRequirement:
    auth_type: str = "BEARER"  # JWT, SESSION, BEARER, API_KEY, OAUTH, RBAC
    mechanism: str = ""
    roles_allowed: List[str] = field(default_factory=list)
    is_enforced: bool = True
    line_number: int = 0

@dataclass
class DiscoveredSourceRoute:
    path: str
    method: str = "GET"
    route_type: str = "BACKEND"  # FRONTEND, BACKEND
    framework: str = "FASTAPI"
    file_path: str = ""
    line_start: int = 1
    line_end: int = 1
    handler_name: str = ""
    auth_required: bool = False
    auth_details: Optional[SourceAuthRequirement] = None
    parameters: List[SourceParameter] = field(default_factory=list)
    request_body_schema: Optional[Dict[str, Any]] = None
    code_snippet: str = ""
    confidence: float = 0.90
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DiscoveredClientCall:
    url_pattern: str
    method: str = "GET"
    file_path: str = ""
    line_number: int = 1
    client_library: str = "fetch"  # fetch, axios, custom_service
    is_dynamic: bool = False
    dynamic_variables: List[str] = field(default_factory=list)
    code_snippet: str = ""
