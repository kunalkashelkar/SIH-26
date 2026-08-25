import logging
import urllib.parse
import networkx as nx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.models.models import Scan, Target, Endpoint, Parameter, Subdomain

logger = logging.getLogger(__name__)

class NodeType:
    TARGET = "TARGET"
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    API = "API"
    ENDPOINT = "ENDPOINT"
    PARAMETER = "PARAMETER"

class EdgeType:
    TARGET_TO_DOMAIN = "HAS_DOMAIN"
    DOMAIN_TO_SUBDOMAIN = "HAS_SUBDOMAIN"
    DOMAIN_TO_ENDPOINT = "HAS_ENDPOINT"
    SUBDOMAIN_TO_ENDPOINT = "HAS_ENDPOINT"
    API_TO_ENDPOINT = "DEFINES_ENDPOINT"
    ENDPOINT_TO_PARAMETER = "HAS_PARAMETER"

class AttackSurfaceGraphBuilder:
    def __init__(self, db: AsyncSession, scan_id: str):
        self.db = db
        self.scan_id = scan_id
        self.graph = nx.DiGraph()

    async def build(self) -> nx.DiGraph:
        """
        Loads all discovered scan assets and builds a NetworkX DiGraph.
        """
        logger.info(f"Building NetworkX attack surface graph for scan {self.scan_id}")
        self.graph.clear()

        # 1. Fetch scan and target
        stmt_scan = (
            select(Scan)
            .options(selectinload(Scan.target))
            .where(Scan.id == self.scan_id)
        )
        res_scan = await self.db.execute(stmt_scan)
        scan = res_scan.scalar_one_or_none()

        if not scan:
            logger.warning(f"Scan {self.scan_id} not found when building graph.")
            return self.graph

        target = scan.target
        target_node_id = f"target_{target.id}" if target else f"target_scan_{self.scan_id}"
        target_name = target.name if target else scan.target_id
        base_url = target.base_url if target else ""

        # Add TARGET node
        self.graph.add_node(
            target_node_id,
            id=target_node_id,
            type=NodeType.TARGET,
            label=target_name,
            metadata={
                "target_id": target.id if target else None,
                "base_url": base_url,
                "scan_id": self.scan_id
            }
        )

        # Extract root domain from target base_url
        parsed_target = urllib.parse.urlparse(base_url)
        root_domain_name = parsed_target.hostname or "localhost"
        domain_node_id = f"domain_{root_domain_name}"

        # Add DOMAIN node
        self.graph.add_node(
            domain_node_id,
            id=domain_node_id,
            type=NodeType.DOMAIN,
            label=root_domain_name,
            metadata={"domain": root_domain_name, "port": parsed_target.port, "scheme": parsed_target.scheme}
        )

        # Edge: TARGET -> DOMAIN
        self.graph.add_edge(
            target_node_id,
            domain_node_id,
            relationship=EdgeType.TARGET_TO_DOMAIN,
            metadata={}
        )

        # 2. Fetch Subdomains
        stmt_sub = select(Subdomain).where(Subdomain.scan_id == self.scan_id)
        res_sub = await self.db.execute(stmt_sub)
        subdomains = res_sub.scalars().all()

        subdomain_nodes = {}
        for sub in subdomains:
            sub_node_id = f"subdomain_{sub.id}"
            subdomain_nodes[sub.domain] = sub_node_id
            self.graph.add_node(
                sub_node_id,
                id=sub_node_id,
                type=NodeType.SUBDOMAIN,
                label=sub.domain,
                metadata={
                    "subdomain_id": sub.id,
                    "domain": sub.domain,
                    "ip_address": sub.ip_address,
                    "is_alive": sub.is_alive
                }
            )
            # Edge: DOMAIN -> SUBDOMAIN
            self.graph.add_edge(
                domain_node_id,
                sub_node_id,
                relationship=EdgeType.DOMAIN_TO_SUBDOMAIN,
                metadata={"ip_address": sub.ip_address}
            )

        # 3. Create API collection nodes if APIs are present
        # API collections can group API endpoints (e.g., OpenAPI definitions or /api paths)
        api_root_node_id = f"api_group_{self.scan_id}"
        has_api_nodes = False

        # 4. Fetch Endpoints & Parameters
        stmt_ep = (
            select(Endpoint)
            .options(selectinload(Endpoint.parameters))
            .where(Endpoint.scan_id == self.scan_id)
        )
        res_ep = await self.db.execute(stmt_ep)
        endpoints = res_ep.scalars().all()

        for ep in endpoints:
            ep_node_id = f"endpoint_{ep.id}"
            ep_label = f"{ep.method} {ep.path}"

            self.graph.add_node(
                ep_node_id,
                id=ep_node_id,
                type=NodeType.ENDPOINT,
                label=ep_label,
                metadata={
                    "endpoint_id": ep.id,
                    "url": ep.url,
                    "path": ep.path,
                    "method": ep.method,
                    "status_code": ep.status_code,
                    "content_type": ep.content_type,
                    "depth": ep.depth,
                    "is_api": ep.is_api,
                    "priority_score": ep.priority_score,
                    "discovered_from": ep.discovered_from
                }
            )

            # Determine parent host (domain or subdomain)
            ep_parsed = urllib.parse.urlparse(ep.url)
            ep_host = ep_parsed.hostname or root_domain_name

            parent_host_node = subdomain_nodes.get(ep_host, domain_node_id)
            
            # Edge: DOMAIN or SUBDOMAIN -> ENDPOINT
            rel_type = EdgeType.SUBDOMAIN_TO_ENDPOINT if parent_host_node != domain_node_id else EdgeType.DOMAIN_TO_ENDPOINT
            self.graph.add_edge(
                parent_host_node,
                ep_node_id,
                relationship=rel_type,
                metadata={"path": ep.path, "method": ep.method}
            )

            # If it's an API, connect to API node
            if ep.is_api:
                if not has_api_nodes:
                    self.graph.add_node(
                        api_root_node_id,
                        id=api_root_node_id,
                        type=NodeType.API,
                        label="REST / OpenAPI Specification",
                        metadata={"scan_id": self.scan_id}
                    )
                    # Connect Target/Domain to API
                    self.graph.add_edge(
                        domain_node_id,
                        api_root_node_id,
                        relationship="HAS_API",
                        metadata={}
                    )
                    has_api_nodes = True

                # Edge: API -> ENDPOINT
                self.graph.add_edge(
                    api_root_node_id,
                    ep_node_id,
                    relationship=EdgeType.API_TO_ENDPOINT,
                    metadata={"method": ep.method, "path": ep.path}
                )

            # 5. Parameters
            for param in ep.parameters:
                param_node_id = f"param_{param.id}"
                param_label = f"{param.location}:{param.name}"

                self.graph.add_node(
                    param_node_id,
                    id=param_node_id,
                    type=NodeType.PARAMETER,
                    label=param_label,
                    metadata={
                        "parameter_id": param.id,
                        "name": param.name,
                        "location": param.location,
                        "value_type": param.value_type
                    }
                )

                # Edge: ENDPOINT -> PARAMETER
                self.graph.add_edge(
                    ep_node_id,
                    param_node_id,
                    relationship=EdgeType.ENDPOINT_TO_PARAMETER,
                    metadata={"location": param.location}
                )

        logger.info(
            f"Graph constructed for scan {self.scan_id} with "
            f"{self.graph.number_of_nodes()} nodes and {self.graph.number_of_edges()} edges."
        )
        return self.graph
