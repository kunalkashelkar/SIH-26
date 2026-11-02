from pydantic import BaseModel, ConfigDict
from typing import Any, Optional

class GraphNode(BaseModel):
    id: str
    type: str  # TARGET, DOMAIN, SUBDOMAIN, API, ENDPOINT, PARAMETER
    label: str
    metadata: dict[str, Any] = {}

class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str  # CONTAINS_DOMAIN, HAS_SUBDOMAIN, HAS_ENDPOINT, DEFINES_ENDPOINT, HAS_PARAMETER
    metadata: dict[str, Any] = {}

class GraphStats(BaseModel):
    total_nodes: int
    total_edges: int
    node_counts_by_type: dict[str, int]
    density: float
    is_connected: bool
    number_connected_components: int
    max_depth: Optional[int] = None
    high_risk_only: Optional[bool] = False
    is_truncated: Optional[bool] = False
    original_total_nodes: Optional[int] = None
    original_total_edges: Optional[int] = None

class GraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    stats: Optional[GraphStats] = None
    model_config = ConfigDict(from_attributes=True)
