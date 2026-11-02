import asyncio
import logging
import urllib.parse
from typing import Dict, Any, Optional, List
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.scanner.http_client import ResilientHttpClient
from app.scanner.discovery.fingerprint import TechnologyFingerprinter
from app.scanner.discovery.sitemap_parser import SitemapDiscoverer
from app.scanner.discovery.static_crawler import StaticHtmlCrawler
from app.scanner.discovery.browser_crawler import PlaywrightDynamicCrawler
from app.scanner.discovery.js_analyzer import JavaScriptAnalyzer
from app.scanner.discovery.api_docs_parser import ApiDocsParser
from app.scanner.discovery.url_parser import is_in_scope, normalize_url
from app.models.models import Endpoint, Parameter, ScanLog
from app.models.discovery import (
    AssetType, DiscoveryStatus, DiscoverySource,
    DiscoveredAsset, DiscoveredEndpoint, EndpointParameter, DiscoveredForm,
    DiscoveryEvent, DiscoveryError, WebsiteProfile
)

logger = logging.getLogger(__name__)

class WebsiteDiscoveryEngine:
    """
    Adaptive, multi-engine website crawler coordinating:
    - Technology Fingerprinting
    - XML Sitemap Parsing
    - BFS Static HTML Crawling & Form Extraction
    - Playwright Dynamic Rendering & Network Interception
    - JavaScript Bundle AST & Regex Analysis
    - OpenAPI/Swagger Specification Extraction
    - Legacy Endpoint Table Synchronization
    """

    def __init__(self, scan_id: str, target_url: str, db: AsyncSession, config: Optional[Dict[str, Any]] = None):
        self.scan_id = scan_id
        self.target_url = target_url.rstrip("/")
        self.db = db
        self.config = config or {}

        # Configuration options
        self.max_depth = self.config.get("max_depth", 3)
        self.max_requests = self.config.get("max_requests", 1000)
        self.enable_playwright = self.config.get("enable_playwright", True)
        self.custom_headers = self.config.get("custom_headers", {})
        self.auth_cookies = self.config.get("auth_cookies", [])

    async def _log(self, level: str, message: str, phase: str = "DISCOVERY"):
        log_entry = ScanLog(scan_id=self.scan_id, level=level, message=message)
        self.db.add(log_entry)
        event = DiscoveryEvent(scan_id=self.scan_id, event_type=level, phase=phase, message=message)
        self.db.add(event)
        await self.db.commit()

    async def run(self, cancel_event: asyncio.Event) -> Dict[str, Any]:
        """Execute the complete website discovery pipeline."""
        await self._log("INFO", f"[WEBSITE_DISCOVERY] Initializing adaptive discovery pipeline for: {self.target_url}")
        
        client = ResilientHttpClient(max_requests=self.max_requests, concurrency=10, timeout=10)
        summary = {
            "sitemap_urls": 0,
            "api_doc_operations": 0,
            "static_pages": 0,
            "dynamic_pages": 0,
            "network_endpoints": 0,
            "js_candidates": 0,
            "total_endpoints_synced": 0
        }

        try:
            # ------------------------------------------------------------------
            # 1. Sitemap Discovery
            # ------------------------------------------------------------------
            if not cancel_event.is_set():
                await self._log("INFO", "[SITEMAP] Inspecting robots.txt and XML sitemap indexes...")
                sitemap_discoverer = SitemapDiscoverer(self.target_url, client, max_depth=2)
                sitemap_urls = await sitemap_discoverer.discover()
                summary["sitemap_urls"] = len(sitemap_urls)
                if sitemap_urls:
                    await self._log("INFO", f"[SITEMAP] Discovered {len(sitemap_urls)} URLs from sitemap XML.")

            # ------------------------------------------------------------------
            # 2. OpenAPI / Swagger Documentation Discovery
            # ------------------------------------------------------------------
            if not cancel_event.is_set():
                await self._log("INFO", "[API_DOCS] Probing for OpenAPI and Swagger definitions...")
                docs_parser = ApiDocsParser(self.target_url, client)
                doc_ops = await docs_parser.discover_and_parse()
                summary["api_doc_operations"] = len(doc_ops)
                
                for op in doc_ops:
                    parsed_path = op["path"]
                    op_method = op["method"]
                    op_url = op["url"]

                    # Persist as DiscoveredAsset
                    asset_stmt = select(DiscoveredAsset).where(
                        DiscoveredAsset.scan_id == self.scan_id,
                        DiscoveredAsset.url == op_url,
                        DiscoveredAsset.method == op_method
                    )
                    asset_res = await self.db.execute(asset_stmt)
                    asset = asset_res.scalar_one_or_none()
                    if not asset:
                        asset = DiscoveredAsset(
                            scan_id=self.scan_id,
                            asset_type=AssetType.BACKEND_API_OPERATION,
                            identifier=f"{op_method} {parsed_path}",
                            name=op.get("summary") or parsed_path,
                            path=parsed_path,
                            url=op_url,
                            method=op_method,
                            discovery_status=DiscoveryStatus.CANDIDATE,
                            confidence=0.9,
                            metadata_json={"operation_id": op.get("operation_id"), "doc_url": op.get("doc_url")}
                        )
                        self.db.add(asset)
                        await self.db.commit()
                        await self.db.refresh(asset)

                    # Persist OpenAPI parameters
                    for p in op.get("parameters", []):
                        p_stmt = select(EndpointParameter).where(
                            EndpointParameter.scan_id == self.scan_id,
                            EndpointParameter.asset_id == asset.id,
                            EndpointParameter.name == p["name"],
                            EndpointParameter.location == p["location"]
                        )
                        p_res = await self.db.execute(p_stmt)
                        if not p_res.scalar_one_or_none():
                            param = EndpointParameter(
                                scan_id=self.scan_id,
                                asset_id=asset.id,
                                name=p["name"],
                                location=p["location"],
                                value_type=p.get("value_type", "string"),
                                is_required=p.get("is_required", False)
                            )
                            self.db.add(param)
                await self.db.commit()

            # ------------------------------------------------------------------
            # 3. Static HTML BFS Crawl & Form Extraction
            # ------------------------------------------------------------------
            discovered_scripts = []
            if not cancel_event.is_set():
                await self._log("INFO", f"[STATIC_CRAWLER] Launching BFS crawler (max_depth={self.max_depth})...")
                static_crawler = StaticHtmlCrawler(
                    scan_id=self.scan_id,
                    target_url=self.target_url,
                    db=self.db,
                    client=client,
                    max_depth=self.max_depth,
                    max_pages=min(self.max_requests, 100),
                    custom_headers=self.custom_headers
                )
                crawl_res = await static_crawler.run(cancel_event)
                summary["static_pages"] = crawl_res.get("pages_crawled", 0)
                discovered_scripts = crawl_res.get("scripts_discovered", [])
                await self._log("SUCCESS", f"[STATIC_CRAWLER] Crawled {summary['static_pages']} static pages, extracted {len(discovered_scripts)} script bundles.")

            # ------------------------------------------------------------------
            # 4. Playwright Dynamic Crawler & Network Interception
            # ------------------------------------------------------------------
            if self.enable_playwright and not cancel_event.is_set():
                await self._log("INFO", "[PLAYWRIGHT] Launching headless browser crawler with network interception...")
                pw_crawler = PlaywrightDynamicCrawler(
                    scan_id=self.scan_id,
                    target_url=self.target_url,
                    db=self.db,
                    max_depth=min(self.max_depth, 2),
                    max_pages=min(self.max_requests, 30),
                    custom_headers=self.custom_headers,
                    auth_cookies=self.auth_cookies
                )
                pw_res = await pw_crawler.run(cancel_event)
                summary["dynamic_pages"] = pw_res.get("pages_crawled", 0)
                summary["network_endpoints"] = pw_res.get("network_endpoints_captured", 0)
                if pw_res.get("status") == "COMPLETED":
                    await self._log("SUCCESS", f"[PLAYWRIGHT] Browser rendered {summary['dynamic_pages']} pages, intercepted {summary['network_endpoints']} APIs.")

            # ------------------------------------------------------------------
            # 5. JavaScript Bundle Analysis
            # ------------------------------------------------------------------
            if discovered_scripts and not cancel_event.is_set():
                await self._log("INFO", f"[JS_ANALYZER] Inspecting {len(discovered_scripts)} client-side JavaScript bundles...")
                js_analyzer = JavaScriptAnalyzer(self.target_url, client)
                js_res = await js_analyzer.analyze_all(discovered_scripts[:15]) # Limit to top 15 bundles
                summary["js_candidates"] = len(js_res.get("api_paths", []))

                for api_path in js_res.get("api_paths", []):
                    full_url = urllib.parse.urljoin(self.target_url + "/", api_path.lstrip("/"))
                    asset_stmt = select(DiscoveredAsset).where(
                        DiscoveredAsset.scan_id == self.scan_id,
                        DiscoveredAsset.url == full_url,
                        DiscoveredAsset.method == "GET"
                    )
                    a_res = await self.db.execute(asset_stmt)
                    if not a_res.scalar_one_or_none():
                        asset = DiscoveredAsset(
                            scan_id=self.scan_id,
                            asset_type=AssetType.BACKEND_API_OPERATION,
                            identifier=f"GET {api_path}",
                            name=api_path,
                            path=api_path,
                            url=full_url,
                            method="GET",
                            discovery_status=DiscoveryStatus.CANDIDATE,
                            confidence=0.7,
                            metadata_json={"source": "javascript_bundle_analysis"}
                        )
                        self.db.add(asset)
                await self.db.commit()

            # ------------------------------------------------------------------
            # 6. Synchronize into Legacy Endpoint & Parameter Tables
            # ------------------------------------------------------------------
            synced_count = await self._sync_to_legacy_tables()
            summary["total_endpoints_synced"] = synced_count

            await self._log("SUCCESS", f"[WEBSITE_DISCOVERY] Pipeline finished. Synchronized {synced_count} unique endpoints for downstream fuzzing.")

        finally:
            await client.close()

        return summary

    async def _sync_to_legacy_tables(self) -> int:
        """
        Synchronizes all DiscoveredAsset records (HTTP_ENDPOINT, BACKEND_API_OPERATION, WEBSITE_PAGE)
        and all associated parameters from EndpointParameter, DiscoveredForm, and URL queries
        into legacy Endpoint and Parameter tables for downstream fuzzing and attack-surface analysis.
        """
        res = await self.db.execute(
            select(DiscoveredAsset).where(
                DiscoveredAsset.scan_id == self.scan_id,
                DiscoveredAsset.asset_type.in_([AssetType.HTTP_ENDPOINT, AssetType.BACKEND_API_OPERATION, AssetType.WEBSITE_PAGE])
            )
        )
        assets = res.scalars().all()
        synced = 0

        for a in assets:
            if not a.url or not a.path:
                continue

            ep_res = await self.db.execute(
                select(Endpoint).where(
                    Endpoint.scan_id == self.scan_id,
                    Endpoint.url == a.url,
                    Endpoint.method == (a.method or "GET")
                )
            )
            legacy_ep = ep_res.scalar_one_or_none()
            if not legacy_ep:
                legacy_ep = Endpoint(
                    id=a.id, # Keep IDs aligned
                    scan_id=self.scan_id,
                    url=a.url,
                    path=a.path,
                    method=a.method or "GET",
                    status_code=a.metadata_json.get("status_code", 200) if a.metadata_json else 200,
                    content_type="text/html" if a.asset_type in [AssetType.HTTP_ENDPOINT, AssetType.WEBSITE_PAGE] else "application/json",
                    depth=a.metadata_json.get("depth", 1) if a.metadata_json else 1,
                    discovered_from=f"discovery_engine:{a.discovery_status}",
                    is_api=a.asset_type == AssetType.BACKEND_API_OPERATION,
                    priority_score=0.0
                )
                self.db.add(legacy_ep)
                synced += 1
                await self.db.flush()

            # 1. Sync parameters from EndpointParameter
            p_res = await self.db.execute(
                select(EndpointParameter).where(
                    EndpointParameter.scan_id == self.scan_id,
                    EndpointParameter.asset_id == a.id
                )
            )
            for p in p_res.scalars().all():
                chk = await self.db.execute(
                    select(Parameter).where(
                        Parameter.endpoint_id == legacy_ep.id,
                        Parameter.name == p.name
                    )
                )
                if not chk.scalar_one_or_none():
                    leg_p = Parameter(
                        endpoint_id=legacy_ep.id,
                        name=p.name,
                        location=p.location or "query",
                        value_type=p.value_type or "string"
                    )
                    self.db.add(leg_p)

            # 2. Sync parameters from DiscoveredForm
            f_res = await self.db.execute(
                select(DiscoveredForm).where(
                    DiscoveredForm.scan_id == self.scan_id,
                    (DiscoveredForm.asset_id == a.id) | (DiscoveredForm.action == a.path) | (DiscoveredForm.page_url == a.url)
                )
            )
            for form in f_res.scalars().all():
                for inp in (form.inputs_schema or []):
                    iname = inp.get("name")
                    if iname:
                        chk = await self.db.execute(
                            select(Parameter).where(
                                Parameter.endpoint_id == legacy_ep.id,
                                Parameter.name == iname
                            )
                        )
                        if not chk.scalar_one_or_none():
                            leg_p = Parameter(
                                endpoint_id=legacy_ep.id,
                                name=iname,
                                location="body" if form.method == "POST" else "query",
                                value_type="string"
                            )
                            self.db.add(leg_p)

            # 3. Sync query parameters from URL path
            if "?" in a.url:
                query_str = a.url.split("?", 1)[1]
                q_vars = urllib.parse.parse_qs(query_str)
                for qname in q_vars.keys():
                    chk = await self.db.execute(
                        select(Parameter).where(
                            Parameter.endpoint_id == legacy_ep.id,
                            Parameter.name == qname
                        )
                    )
                    if not chk.scalar_one_or_none():
                        leg_p = Parameter(
                            endpoint_id=legacy_ep.id,
                            name=qname,
                            location="query",
                            value_type="string"
                        )
                        self.db.add(leg_p)

        await self.db.commit()
        return synced
