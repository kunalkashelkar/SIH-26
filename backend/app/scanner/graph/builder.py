import logging
import urllib.parse
import networkx as nx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.models.models import Scan, Target, Endpoint, Parameter, Subdomain, VirtualHost, Finding

logger = logging.getLogger(__name__)

class NodeType:
    TARGET = "TARGET"
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    VIRTUAL_HOST = "VIRTUAL_HOST"
    API = "API"
    ENDPOINT = "ENDPOINT"
    PARAMETER = "PARAMETER"
    FINDING = "FINDING"

class EdgeType:
    TARGET_TO_DOMAIN = "HAS_DOMAIN"
    DOMAIN_TO_SUBDOMAIN = "HAS_SUBDOMAIN"
    DOMAIN_TO_VHOST = "HAS_VIRTUAL_HOST"
    DOMAIN_TO_ENDPOINT = "HAS_ENDPOINT"
    SUBDOMAIN_TO_ENDPOINT = "HAS_ENDPOINT"
    VHOST_TO_ENDPOINT = "HAS_ENDPOINT"
    API_TO_ENDPOINT = "DEFINES_ENDPOINT"
    ENDPOINT_TO_PARAMETER = "HAS_PARAMETER"
    ENDPOINT_TO_FINDING = "HAS_FINDING"
    PARAMETER_TO_FINDING = "HAS_FINDING"

class AttackSurfaceGraphBuilder:
    def __init__(self, db: AsyncSession, scan_id: str, max_depth: int | None = None):
        self.db = db
        self.scan_id = scan_id
        self.max_depth = max_depth
        self.graph = nx.DiGraph()

    async def build(self) -> nx.DiGraph:
        """
        Loads all discovered scan assets and verified findings, building a complete NetworkX DiGraph.
        """
        logger.info(f"Building NetworkX attack surface graph for scan {self.scan_id} (max_depth={self.max_depth})")
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

        # 3. Fetch Virtual Hosts
        stmt_vhost = select(VirtualHost).where(VirtualHost.scan_id == self.scan_id)
        res_vhost = await self.db.execute(stmt_vhost)
        vhosts = res_vhost.scalars().all()

        vhost_nodes = {}
        for vh in vhosts:
            vh_node_id = f"vhost_{vh.id}"
            vhost_nodes[vh.host] = vh_node_id
            self.graph.add_node(
                vh_node_id,
                id=vh_node_id,
                type=NodeType.VIRTUAL_HOST,
                label=vh.host,
                metadata={
                    "vhost_id": vh.id,
                    "host": vh.host,
                    "ip_address": vh.ip_address,
                    "status_code": vh.status_code,
                    "is_active": vh.is_active
                }
            )
            parent_dom = subdomain_nodes.get(vh.host, domain_node_id)
            self.graph.add_edge(
                parent_dom,
                vh_node_id,
                relationship=EdgeType.DOMAIN_TO_VHOST,
                metadata={}
            )

        # 4. Create API collection nodes if APIs are present
        api_root_node_id = f"api_group_{self.scan_id}"
        has_api_nodes = False

        # 5. Fetch Endpoints & Parameters
        ep_query = (
            select(Endpoint)
            .options(selectinload(Endpoint.parameters))
            .where(Endpoint.scan_id == self.scan_id)
        )
        if self.max_depth is not None and self.max_depth > 0:
            ep_query = ep_query.where(Endpoint.depth <= self.max_depth)

        res_ep = await self.db.execute(ep_query)
        endpoints = res_ep.scalars().all()

        endpoint_node_map = {}
        param_node_map = {}

        for ep in endpoints:
            ep_node_id = f"endpoint_{ep.id}"
            endpoint_node_map[ep.id] = ep_node_id
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

            # Determine parent host (domain, subdomain, or vhost)
            ep_parsed = urllib.parse.urlparse(ep.url)
            ep_host = ep_parsed.hostname or root_domain_name

            if ep_host in vhost_nodes:
                parent_host_node = vhost_nodes[ep_host]
                rel_type = EdgeType.VHOST_TO_ENDPOINT
            elif ep_host in subdomain_nodes:
                parent_host_node = subdomain_nodes[ep_host]
                rel_type = EdgeType.SUBDOMAIN_TO_ENDPOINT
            else:
                parent_host_node = domain_node_id
                rel_type = EdgeType.DOMAIN_TO_ENDPOINT

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
                    self.graph.add_edge(
                        domain_node_id,
                        api_root_node_id,
                        relationship="HAS_API",
                        metadata={}
                    )
                    has_api_nodes = True

                self.graph.add_edge(
                    api_root_node_id,
                    ep_node_id,
                    relationship=EdgeType.API_TO_ENDPOINT,
                    metadata={"method": ep.method, "path": ep.path}
                )

            # Parameters
            for param in ep.parameters:
                param_node_id = f"param_{param.id}"
                param_node_map[param.id] = param_node_id
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

                self.graph.add_edge(
                    ep_node_id,
                    param_node_id,
                    relationship=EdgeType.ENDPOINT_TO_PARAMETER,
                    metadata={"location": param.location}
                )

        # 6. Fetch Confirmed Findings & Link to Endpoints / Parameters
        stmt_findings = select(Finding).where(Finding.scan_id == self.scan_id)
        res_findings = await self.db.execute(stmt_findings)
        findings = res_findings.scalars().all()

        for f in findings:
            finding_node_id = f"finding_{f.id}"
            finding_label = f"{f.severity}: {f.vulnerability_type}"

            self.graph.add_node(
                finding_node_id,
                id=finding_node_id,
                type=NodeType.FINDING,
                label=finding_label,
                metadata={
                    "finding_id": f.id,
                    "vulnerability_type": f.vulnerability_type,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "priority": f.priority,
                    "cwe": f.cwe,
                    "owasp_category": f.owasp_category,
                    "status": f.status
                }
            )

            # Connect finding to Parameter if available, otherwise Endpoint
            if f.parameter_id and f.parameter_id in param_node_map:
                self.graph.add_edge(
                    param_node_map[f.parameter_id],
                    finding_node_id,
                    relationship=EdgeType.PARAMETER_TO_FINDING,
                    metadata={"severity": f.severity}
                )
            elif f.endpoint_id and f.endpoint_id in endpoint_node_map:
                self.graph.add_edge(
                    endpoint_node_map[f.endpoint_id],
                    finding_node_id,
                    relationship=EdgeType.ENDPOINT_TO_FINDING,
                    metadata={"severity": f.severity}
                )
            else:
                # Fallback to domain node
                self.graph.add_edge(
                    domain_node_id,
                    finding_node_id,
                    relationship="HAS_FINDING",
                    metadata={"severity": f.severity}
                )

        logger.info(
            f"Graph constructed for scan {self.scan_id} with "
            f"{self.graph.number_of_nodes()} nodes and {self.graph.number_of_edges()} edges."
        )
        return self.graph
