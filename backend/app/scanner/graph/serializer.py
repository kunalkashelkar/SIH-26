import networkx as nx
from typing import Any

from app.scanner.graph.queries import GraphQueries
from app.schemas.graph import GraphNode, GraphEdge, GraphStats, GraphResponse

class GraphSerializer:
    @staticmethod
    def serialize(graph: nx.DiGraph) -> dict[str, Any]:
        """
        Serializes NetworkX DiGraph into a dictionary conforming to GraphResponse schema.
        """
        nodes: list[dict[str, Any]] = []
        for node_id, data in graph.nodes(data=True):
            nodes.append({
                "id": node_id,
                "type": data.get("type", "UNKNOWN"),
                "label": data.get("label", str(node_id)),
                "metadata": data.get("metadata", {})
            })

        edges: list[dict[str, Any]] = []
        for u, v, data in graph.edges(data=True):
            edges.append({
                "source": u,
                "target": v,
                "relationship": data.get("relationship", "RELATED_TO"),
                "metadata": data.get("metadata", {})
            })

        metrics = GraphQueries.calculate_metrics(graph)
        stats = {
            "total_nodes": metrics.get("total_nodes", 0),
            "total_edges": metrics.get("total_edges", 0),
            "node_counts_by_type": metrics.get("node_counts_by_type", {}),
            "density": metrics.get("density", 0.0),
            "is_connected": metrics.get("is_connected", False),
            "number_connected_components": metrics.get("number_connected_components", 0)
        }

        return {
            "nodes": nodes,
            "edges": edges,
            "stats": stats
        }
