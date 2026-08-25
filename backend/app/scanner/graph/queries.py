import logging
import networkx as nx
from typing import Any

from app.scanner.graph.builder import NodeType

logger = logging.getLogger(__name__)

class GraphQueries:
    @staticmethod
    def calculate_metrics(graph: nx.DiGraph) -> dict[str, Any]:
        """
        Calculates basic graph properties, statistics, and connectivity metrics.
        """
        if not graph or graph.number_of_nodes() == 0:
            return {
                "total_nodes": 0,
                "total_edges": 0,
                "node_counts_by_type": {},
                "density": 0.0,
                "is_connected": False,
                "number_connected_components": 0
            }

        # Count nodes by type
        node_counts = {}
        for _, data in graph.nodes(data=True):
            ntype = data.get("type", "UNKNOWN")
            node_counts[ntype] = node_counts.get(ntype, 0) + 1

        density = nx.density(graph)

        # For directed graphs, check weakly connected components
        num_wcc = nx.number_weakly_connected_components(graph)
        is_wcc = nx.is_weakly_connected(graph)

        # Centrality metrics for prioritization
        degree_centrality = nx.degree_centrality(graph)
        in_degrees = dict(graph.in_degree())
        out_degrees = dict(graph.out_degree())

        return {
            "total_nodes": graph.number_of_nodes(),
            "total_edges": graph.number_of_edges(),
            "node_counts_by_type": node_counts,
            "density": round(density, 4),
            "is_connected": is_wcc,
            "number_connected_components": num_wcc,
            "degree_centrality": degree_centrality,
            "in_degrees": in_degrees,
            "out_degrees": out_degrees
        }

    @staticmethod
    def get_endpoints_by_priority(graph: nx.DiGraph) -> list[dict[str, Any]]:
        """
        Extracts endpoints sorted by degree / parameter density and priority score.
        """
        endpoints = []
        for node_id, data in graph.nodes(data=True):
            if data.get("type") == NodeType.ENDPOINT:
                # Out-degree usually corresponds to parameters attached to this endpoint
                out_deg = graph.out_degree(node_id)
                meta = data.get("metadata", {})
                priority = meta.get("priority_score", 0.0)
                
                endpoints.append({
                    "node_id": node_id,
                    "endpoint_id": meta.get("endpoint_id"),
                    "path": meta.get("path"),
                    "method": meta.get("method"),
                    "parameter_count": out_deg,
                    "priority_score": priority
                })

        endpoints.sort(key=lambda x: (x["priority_score"], x["parameter_count"]), reverse=True)
        return endpoints

    @staticmethod
    def get_attack_surface_coverage(graph: nx.DiGraph) -> dict[str, Any]:
        """
        Analyzes coverage across endpoints, subdomains, APIs, and parameters.
        """
        counts = {}
        for _, data in graph.nodes(data=True):
            ntype = data.get("type", "UNKNOWN")
            counts[ntype] = counts.get(ntype, 0) + 1

        total_endpoints = counts.get(NodeType.ENDPOINT, 0)
        total_params = counts.get(NodeType.PARAMETER, 0)
        total_apis = counts.get(NodeType.API, 0)
        total_subdomains = counts.get(NodeType.SUBDOMAIN, 0)

        # Endpoints with at least one parameter
        parameterized_endpoints = 0
        for node_id, data in graph.nodes(data=True):
            if data.get("type") == NodeType.ENDPOINT and graph.out_degree(node_id) > 0:
                parameterized_endpoints += 1

        return {
            "total_endpoints": total_endpoints,
            "parameterized_endpoints": parameterized_endpoints,
            "total_parameters": total_params,
            "total_apis": total_apis,
            "total_subdomains": total_subdomains,
            "fuzzable_surface_ratio": (
                round(parameterized_endpoints / total_endpoints, 2) if total_endpoints > 0 else 0.0
            )
        }
