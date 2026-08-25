from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class DiscoveredParameter:
    name: str
    location: str # "query", "body", "path", "header"
    value_type: str = "unknown"
    
    @staticmethod
    def infer_type(val: str, name: str) -> str:
        if not val:
            # Guess by name
            name_lower = name.lower()
            if "id" in name_lower or "uuid" in name_lower: return "identifier"
            if "is_" in name_lower or "has_" in name_lower: return "boolean"
            return "string"
        
        if val.isdigit(): return "numeric"
        if val.lower() in ("true", "false", "1", "0"): return "boolean"
        # simple heuristic for uuid/identifiers
        if len(val) > 16 and "-" in val and val.replace("-", "").isalnum(): return "identifier"
        return "string"

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
