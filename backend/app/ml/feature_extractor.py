from __future__ import annotations

import ipaddress
import urllib.parse
from collections import defaultdict
from typing import Iterable

import networkx as nx

from app.models.models import Endpoint, Scan, Subdomain, VirtualHost


STATIC_EXTENSIONS = {
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
    ".pdf",
    ".zip",
}


def endpoint_host(url: str) -> str:
    """
    Extract hostname from an endpoint URL.
    """
    return (
        urllib.parse.urlparse(url or "").hostname
        or ""
    ).lower()


def endpoint_type(endpoint: Endpoint) -> str:
    """
    Classify endpoint as API, static or normal web endpoint.
    """

    if bool(endpoint.is_api):
        return "api"

    path = (endpoint.path or "").lower()

    if any(path.endswith(ext) for ext in STATIC_EXTENSIONS):
        return "static"

    content_type = (endpoint.content_type or "").lower()

    if "json" in content_type or "xml" in content_type:
        return "api"

    if path.startswith("/api/") or path == "/api":
        return "api"

    return "web"


def is_external_host(host: str) -> int:
    """
    Conservative external-exposure heuristic.

    Public DNS names -> 1
    localhost/private IPs -> 0

    This is a feature for prioritization, not proof
    that the endpoint is reachable from the Internet.
    """

    host = (host or "").lower().strip()

    if not host:
        return 0

    if host in {
        "localhost",
        "localhost.localdomain",
    } or host.endswith(".local"):
        return 0

    try:
        ip = ipaddress.ip_address(host)

        return int(
            not (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
            )
        )

    except ValueError:
        # Normal DNS hostname
        return 1


def build_pre_fuzz_graph(
    scan: Scan,
    endpoints: Iterable[Endpoint],
    subdomains: Iterable[Subdomain],
    vhosts: Iterable[VirtualHost],
):
    """
    Build attack-surface graph using ONLY information
    available before fuzzing.

    IMPORTANT:
    Findings and FuzzResults are NOT added.

    This prevents target leakage.
    """

    graph = nx.DiGraph()

    endpoint_nodes = {}
    host_parent = {}
    subdomain_set = set()

    base_url = scan.target.base_url if scan.target else ""

    parsed = urllib.parse.urlparse(base_url)

    root_host = (
        parsed.hostname
        or "localhost"
    ).lower()

    target_node = f"target_{scan.target_id}"
    domain_node = f"domain_{root_host}"

    graph.add_node(
        target_node,
        type="TARGET"
    )

    graph.add_node(
        domain_node,
        type="DOMAIN"
    )

    graph.add_edge(
        target_node,
        domain_node
    )

    # -----------------------------
    # SUBDOMAINS
    # -----------------------------

    for sub in subdomains:

        host = (
            sub.domain
            or ""
        ).lower()

        node = f"subdomain_{sub.id}"

        graph.add_node(
            node,
            type="SUBDOMAIN"
        )

        graph.add_edge(
            domain_node,
            node
        )

        host_parent[host] = node
        subdomain_set.add(host)

    # -----------------------------
    # VHOSTS
    # -----------------------------

    vhost_set = set()

    for vh in vhosts:

        host = (
            vh.host
            or ""
        ).lower()

        node = f"vhost_{vh.id}"

        graph.add_node(
            node,
            type="VIRTUAL_HOST"
        )

        graph.add_edge(
            host_parent.get(
                host,
                domain_node
            ),
            node
        )

        host_parent[host] = node
        vhost_set.add(host)

    # -----------------------------
    # ENDPOINTS
    # -----------------------------

    api_node = f"api_group_{scan.id}"
    has_api = False

    for endpoint in endpoints:

        node = f"endpoint_{endpoint.id}"

        endpoint_nodes[
            endpoint.id
        ] = node

        graph.add_node(
            node,
            type="ENDPOINT"
        )

        host = (
            endpoint_host(endpoint.url)
            or root_host
        )

        parent = host_parent.get(
            host,
            domain_node
        )

        graph.add_edge(
            parent,
            node
        )

        # API relationship
        if endpoint.is_api:

            has_api = True

            graph.add_node(
                api_node,
                type="API"
            )

            graph.add_edge(
                domain_node,
                api_node
            )

            graph.add_edge(
                api_node,
                node
            )

        # Parameters
        for parameter in (
            endpoint.parameters or []
        ):

            parameter_node = (
                f"param_{parameter.id}"
            )

            graph.add_node(
                parameter_node,
                type="PARAMETER"
            )

            graph.add_edge(
                node,
                parameter_node
            )

    if not has_api and api_node in graph:
        graph.remove_node(api_node)

    return (
        graph,
        endpoint_nodes,
        host_parent,
        subdomain_set,
        vhost_set,
    )


def extract_endpoint_features(
    scan,
    endpoint,
    graph,
    endpoint_nodes,
    host_parent,
    subdomain_set,
    vhost_set,
    related_endpoints_by_parent,
    api_endpoint_count,
    historical_anomaly_count,
    historical_scan_count,
):
    """
    Convert one Endpoint into the ML feature vector.
    """

    host = endpoint_host(
        endpoint.url
    )

    parameters = list(
        endpoint.parameters or []
    )

    query_count = sum(
        1
        for parameter in parameters
        if (
            parameter.location
            or ""
        ).lower() == "query"
    )

    body_count = sum(
        1
        for parameter in parameters
        if (
            parameter.location
            or ""
        ).lower() == "body"
    )

    node = endpoint_nodes[
        endpoint.id
    ]

    parent = host_parent.get(host)

    return {

        # Identifiers
        "endpoint_id": endpoint.id,
        "scan_id": scan.id,
        "target_id": scan.target_id,

        # Endpoint
        "http_method": (
            endpoint.method
            or "GET"
        ).upper(),

        "endpoint_depth": int(
            endpoint.depth or 0
        ),

        "endpoint_type": endpoint_type(
            endpoint
        ),

        # Parameters
        "parameter_count": len(
            parameters
        ),

        "query_parameter_count": (
            query_count
        ),

        "body_parameter_count": (
            body_count
        ),

        # Security context
        "authentication_required": int(
            endpoint.status_code
            in {401, 403}
        ),

        "external_exposure": (
            is_external_host(host)
        ),

        # Attack-surface graph
        "graph_degree": int(
            graph.degree(node)
        ),

        "related_endpoint_count": max(
            0,
            len(
                related_endpoints_by_parent.get(
                    parent,
                    set()
                )
            ) - 1
        ),

        "api_relationship_count": (
            int(endpoint.is_api)
        ),

        "subdomain_relationship": int(
            host in subdomain_set
        ),

        "vhost_relationship": int(
            host in vhost_set
        ),

        # Historical context
        "historical_anomaly_count": (
            historical_anomaly_count
        ),

        "historical_scan_count": (
            historical_scan_count
        ),
    }