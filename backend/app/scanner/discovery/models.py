from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class DiscoveredParameter:
    name: str
    location: str # "query", "body", "path", "header"
    value_type: str = "string"

@dataclass
class DiscoveredEndpoint:
    url: str
    path: str
    method: str
    depth: int
    discovered_from: Optional[str] = None
    is_api: bool = False
    content_type: Optional[str] = None
    status_code: Optional[int] = None
    parameters: List[DiscoveredParameter] = field(default_factory=list)
