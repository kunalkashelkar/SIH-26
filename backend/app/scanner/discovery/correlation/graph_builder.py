"""
Unified Multi-Layer Attack Surface Graph Builder.
Constructs a NetworkX directed graph modeling:
Website -> Frontend Page -> Component -> API Client -> ApiEndpoint -> Backend Controller -> Auth Dependency / Schema.
Preserves verifiable source and runtime evidence on all nodes and edges.
"""
import logging
import networkx as nx
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class UnifiedGraphNodeType:
    WEBSITE = "WEBSITE"
    FRONTEND_PAGE = "FRONTEND_PAGE"
    FRONTEND_ROUTE = "FRONTEND_ROUTE"
    COMPONENT = "COMPONENT"
    FORM = "FORM"
    API_CLIENT = "API_CLIENT"
    API_ENDPOINT = "API_ENDPOINT"
    BACKEND_CONTROLLER = "BACKEND_CONTROLLER"
    MIDDLEWARE = "MIDDLEWARE"
    AUTH_DEPENDENCY = "AUTH_DEPENDENCY"
    PARAMETER = "PARAMETER"
    SOURCE_FILE = "SOURCE_FILE"

class UnifiedGraphEdgeType:
    CONTAINS = "CONTAINS"
    RENDERS_PAGE = "RENDERS_PAGE"
    INCLUDES_COMPONENT = "INCLUDES_COMPONENT"
    INVOKES_API = "INVOKES_API"
    SUBMITS_FORM = "SUBMITS_FORM"
    ROUTES_TO = "ROUTES_TO"
    DEFINED_IN = "DEFINED_IN"
    PROTECTED_BY = "PROTECTED_BY"
    VALIDATES_WITH = "VALIDATES_WITH"
    HAS_PARAMETER = "HAS_PARAMETER"

class UnifiedAttackSurfaceGraphBuilder:
    """
    Constructs a rich, queryable NetworkX directed graph from correlated discovery inventories.
    """

    def __init__(self, scan_id: str, website_url: Optional[str] = None, repo_url: Optional[str] = None):
        self.scan_id = scan_id
        self.website_url = website_url
        self.repo_url = repo_url
        self.graph = nx.DiGraph()

    def build_graph(
        self,
        assets: List[Dict[str, Any]],
        routes: List[Dict[str, Any]],
        forms: List[Dict[str, Any]],
        client_calls: List[Dict[str, Any]],
        auth_observations: List[Dict[str, Any]],
        relationships: List[Dict[str, Any]]
    ) -> nx.DiGraph:
        self.graph.clear()

        # 1. Root Target Nodes
        if self.website_url:
            self.graph.add_node(
                "root_website",
                id="root_website",
                type=UnifiedGraphNodeType.WEBSITE,
                label=self.website_url,
                metadata={"url": self.website_url, "scan_id": self.scan_id}
            )

        if self.repo_url:
            self.graph.add_node(
                "root_repository",
                id="root_repository",
                type=UnifiedGraphNodeType.SOURCE_FILE,
                label=self.repo_url,
                metadata={"repo_url": self.repo_url, "scan_id": self.scan_id}
            )

        # 2. Add Discovered Assets
        for asset in assets:
            a_id = asset["id"]
            a_type = asset.get("asset_type")
            label = f"{asset.get('method', 'GET')} {asset.get('path', '/')}"

            node_type = UnifiedGraphNodeType.API_ENDPOINT
            if a_type == "WEBSITE_PAGE":
                node_type = UnifiedGraphNodeType.FRONTEND_PAGE
            elif a_type == "FRONTEND_ROUTE":
                node_type = UnifiedGraphNodeType.FRONTEND_ROUTE

            self.graph.add_node(
                a_id,
                id=a_id,
                type=node_type,
                label=label,
                discovery_status=asset.get("discovery_status", "UNKNOWN"),
                confidence=asset.get("confidence", 1.0),
                metadata=asset.get("metadata_json", {})
            )

            # Link page to root website
            if node_type == UnifiedGraphNodeType.FRONTEND_PAGE and "root_website" in self.graph:
                self.graph.add_edge(
                    "root_website", a_id,
                    type=UnifiedGraphEdgeType.CONTAINS,
                    label="CONTAINS_PAGE"
                )

        # 3. Add Forms and Form -> Endpoint Submissions
        for form in forms:
            f_id = form["id"]
            f_label = f"Form: {form.get('method', 'POST')} {form.get('action', '/')}"
            self.graph.add_node(
                f_id,
                id=f_id,
                type=UnifiedGraphNodeType.FORM,
                label=f_label,
                metadata=form
            )

            # Connect page to form
            page_url = form.get("page_url")
            for node, data in list(self.graph.nodes(data=True)):
                if data.get("type") == UnifiedGraphNodeType.FRONTEND_PAGE and data.get("metadata", {}).get("url") == page_url:
                    self.graph.add_edge(node, f_id, type=UnifiedGraphEdgeType.CONTAINS, label="HAS_FORM")

            # Connect form to action API endpoint
            action = form.get("action")
            for node, data in list(self.graph.nodes(data=True)):
                if data.get("type") == UnifiedGraphNodeType.API_ENDPOINT and data.get("label", "").endswith(action or ""):
                    self.graph.add_edge(f_id, node, type=UnifiedGraphEdgeType.SUBMITS_FORM, label="SUBMITS_TO")

        # 4. Add Source Controllers & Handlers
        for route in routes:
            r_id = route.get("id") or f"route_{route.get('handler_name')}"
            handler = route.get("handler_name") or "controller"
            framework = route.get("framework", "FASTAPI")
            
            ctrl_node_id = f"ctrl_{handler}_{route.get('source_file')}"
            if ctrl_node_id not in self.graph:
                self.graph.add_node(
                    ctrl_node_id,
                    id=ctrl_node_id,
                    type=UnifiedGraphNodeType.BACKEND_CONTROLLER,
                    label=f"{framework}: {handler}",
                    metadata={"file": route.get("source_file"), "line": route.get("source_line")}
                )

            # Connect API endpoint to Backend Controller
            asset_id = route.get("asset_id")
            if asset_id and asset_id in self.graph:
                self.graph.add_edge(
                    asset_id, ctrl_node_id,
                    type=UnifiedGraphEdgeType.ROUTES_TO,
                    label="HANDLED_BY"
                )

            # If Auth is required, add Auth Dependency node
            if route.get("auth_required"):
                auth_node_id = f"auth_{ctrl_node_id}"
                if auth_node_id not in self.graph:
                    self.graph.add_node(
                        auth_node_id,
                        id=auth_node_id,
                        type=UnifiedGraphNodeType.AUTH_DEPENDENCY,
                        label="Auth Guard / Dependency",
                        metadata={"file": route.get("source_file")}
                    )
                self.graph.add_edge(
                    ctrl_node_id, auth_node_id,
                    type=UnifiedGraphEdgeType.PROTECTED_BY,
                    label="REQUIRES_AUTH"
                )

        # 5. Add Frontend Client Calls (e.g. React Component -> API Client -> ApiEndpoint)
        for call in client_calls:
            call_id = f"client_{call.get('file_path')}_{call.get('line_number')}"
            call_label = f"{call.get('client_library', 'api')}.{call.get('method', 'GET')}({call.get('url_pattern')})"
            
            self.graph.add_node(
                call_id,
                id=call_id,
                type=UnifiedGraphNodeType.API_CLIENT,
                label=call_label,
                metadata=call
            )

            # Find matching API endpoint
            pattern = call.get("url_pattern", "")
            for node, data in list(self.graph.nodes(data=True)):
                if data.get("type") == UnifiedGraphNodeType.API_ENDPOINT and pattern in data.get("label", ""):
                    self.graph.add_edge(
                        call_id, node,
                        type=UnifiedGraphEdgeType.INVOKES_API,
                        label="CALLS"
                    )

        # 6. Explicit Correlations & Relationships
        for rel in relationships:
            s_id = rel.get("source_asset_id")
            t_id = rel.get("target_asset_id")
            r_type = rel.get("relationship_type", "CORRELATED_WITH")
            if s_id in self.graph and t_id in self.graph:
                self.graph.add_edge(
                    s_id, t_id,
                    type=r_type,
                    label=r_type,
                    confidence=rel.get("confidence", 1.0),
                    metadata=rel.get("metadata_json", {})
                )

        logger.info(f"Unified Attack Surface Graph built: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges.")
        return self.graph

    def to_json(self) -> Dict[str, Any]:
        """Serializes the NetworkX graph to standard JSON node/edge format."""
        nodes = []
        for n_id, attrs in self.graph.nodes(data=True):
            nodes.append({
                "id": str(n_id),
                "type": attrs.get("type", "UNKNOWN"),
                "label": attrs.get("label", str(n_id)),
                "discovery_status": attrs.get("discovery_status"),
                "confidence": attrs.get("confidence"),
                "metadata": attrs.get("metadata", {})
            })

        edges = []
        for u, v, attrs in self.graph.edges(data=True):
            edges.append({
                "source": str(u),
                "target": str(v),
                "type": attrs.get("type", "CONNECTED"),
                "label": attrs.get("label", ""),
                "confidence": attrs.get("confidence", 1.0),
                "metadata": attrs.get("metadata", {})
            })

        return {
            "scan_id": self.scan_id,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "nodes": nodes,
            "edges": edges
        }
