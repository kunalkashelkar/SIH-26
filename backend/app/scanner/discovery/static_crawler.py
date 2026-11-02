import asyncio
import logging
import urllib.parse
from bs4 import BeautifulSoup
from typing import Set, List, Dict, Any, Optional
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.scanner.http_client import ResilientHttpClient
from app.scanner.discovery.url_parser import is_in_scope, normalize_url
from app.scanner.discovery.fingerprint import TechnologyFingerprinter
from app.models.discovery import (
    AssetType, DiscoveryStatus, DiscoverySource,
    DiscoveredAsset, DiscoveredPage, DiscoveredForm,
    DiscoveredEndpoint, EndpointParameter, RuntimeEvidence, WebsiteProfile
)

logger = logging.getLogger(__name__)

class StaticHtmlCrawler:
    """
    High-performance static HTML crawler.
    Performs BFS traversal, extracts links, forms, input fields, scripts,
    fingerprints technologies, and records rich discovery assets into the database.
    """

    def __init__(
        self,
        scan_id: str,
        target_url: str,
        db: AsyncSession,
        client: ResilientHttpClient,
        max_depth: int = 3,
        max_pages: int = 200,
        custom_headers: Optional[Dict[str, str]] = None
    ):
        self.scan_id = scan_id
        self.target_url = target_url.rstrip("/")
        self.db = db
        self.client = client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.custom_headers = custom_headers or {}

        self.visited_urls: Set[str] = set()
        self.queue: asyncio.Queue = asyncio.Queue()
        self.discovered_scripts: Set[str] = set()

    async def run(self, cancel_event: asyncio.Event) -> Dict[str, Any]:
        """Execute BFS crawl."""
        logger.info(f"[STATIC_CRAWLER] Starting BFS crawl for {self.target_url} (depth={self.max_depth}, limit={self.max_pages})")
        
        # Enqueue root
        await self.queue.put((self.target_url, 0))
        pages_processed = 0

        while not self.queue.empty() and not cancel_event.is_set():
            if pages_processed >= self.max_pages:
                logger.info(f"[STATIC_CRAWLER] Reached page limit budget ({self.max_pages})")
                break

            current_url, depth = await self.queue.get()
            if current_url in self.visited_urls or depth > self.max_depth:
                self.queue.task_done()
                continue

            self.visited_urls.add(current_url)
            pages_processed += 1

            try:
                await self._process_page(current_url, depth, cancel_event)
            except Exception as e:
                logger.debug(f"[STATIC_CRAWLER] Error fetching {current_url}: {e}")
            finally:
                self.queue.task_done()

        return {
            "pages_crawled": len(self.visited_urls),
            "scripts_discovered": list(self.discovered_scripts)
        }

    async def _process_page(self, url: str, depth: int, cancel_event: asyncio.Event):
        if cancel_event.is_set():
            return

        resp = await self.client._request("GET", url, headers=self.custom_headers)
        if not resp:
            return

        status_code = resp.status_code
        content_type = resp.headers.get("content-type", "").lower()
        content = resp.text
        final_url = str(resp.url) if hasattr(resp, "url") and resp.url else url

        # Fingerprint target on root page
        if depth == 0:
            techs, archs = TechnologyFingerprinter.fingerprint(resp.headers, content)
            web_res = await self.db.execute(select(WebsiteProfile).where(WebsiteProfile.scan_id == self.scan_id))
            web_profile = web_res.scalar_one_or_none()
            if web_profile:
                web_profile.tech_stack = techs
                web_profile.security_headers = {
                    k: v for k, v in resp.headers.items() 
                    if k.lower() in ["content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options"]
                }
                await self.db.commit()

        # Only parse HTML documents
        if "text/html" not in content_type:
            return

        soup = BeautifulSoup(content, "html.parser")
        title = soup.title.string.strip() if (soup.title and soup.title.string) else ""
        forms = soup.find_all("form")
        links = soup.find_all("a", href=True)
        scripts = soup.find_all("script", src=True)

        has_auth_form = False
        parsed_url = urllib.parse.urlparse(url)

        # 1. Record DiscoveredAsset for this Page
        page_asset_id = f"page_{hash(url)}"
        asset_res = await self.db.execute(select(DiscoveredAsset).where(DiscoveredAsset.scan_id == self.scan_id, DiscoveredAsset.url == url))
        existing_asset = asset_res.scalar_one_or_none()
        
        if not existing_asset:
            existing_asset = DiscoveredAsset(
                scan_id=self.scan_id,
                asset_type=AssetType.WEBSITE_PAGE,
                identifier=f"PAGE {parsed_url.path or '/'}",
                name=title or parsed_url.path or "/",
                path=parsed_url.path or "/",
                url=url,
                method="GET",
                discovery_status=DiscoveryStatus.RUNTIME_OBSERVED,
                confidence=1.0,
                metadata_json={"title": title, "status_code": status_code, "depth": depth}
            )
            self.db.add(existing_asset)
            await self.db.commit()
            await self.db.refresh(existing_asset)
        else:
            # Confirmed at runtime as an HTML webpage
            existing_asset.asset_type = AssetType.WEBSITE_PAGE
            existing_asset.discovery_status = DiscoveryStatus.RUNTIME_OBSERVED
            if title:
                existing_asset.name = title
            meta = dict(existing_asset.metadata_json or {})
            meta.update({"title": title, "status_code": status_code, "depth": depth, "is_html_page": True})
            existing_asset.metadata_json = meta
            await self.db.commit()

        # 2. Record DiscoveredPage
        discovered_page = DiscoveredPage(
            scan_id=self.scan_id,
            asset_id=existing_asset.id,
            url=url,
            title=title,
            status_code=status_code,
            content_type=content_type,
            response_size=len(content),
            dom_elements_count=len(soup.find_all()),
            forms_count=len(forms),
            links_count=len(links),
            has_auth_form=False,
            metadata_json={"depth": depth}
        )
        self.db.add(discovered_page)

        # 3. Add RuntimeEvidence
        ev = RuntimeEvidence(
            scan_id=self.scan_id,
            asset_id=existing_asset.id,
            discovery_source=DiscoverySource.STATIC_HTML,
            observation_type="PAGE_LOAD",
            url=url,
            method="GET",
            response_status=status_code,
            confidence=1.0,
            verification_status=DiscoveryStatus.RUNTIME_OBSERVED,
            evidence_reference=f"Static HTML page crawled: status {status_code}"
        )
        self.db.add(ev)

        # 3b. Extract Query Parameters from Page URL
        if parsed_url.query:
            qs_dict = urllib.parse.parse_qs(parsed_url.query)
            for q_name, q_vals in qs_dict.items():
                p_stmt = select(EndpointParameter).where(
                    EndpointParameter.scan_id == self.scan_id,
                    EndpointParameter.asset_id == existing_asset.id,
                    EndpointParameter.name == q_name,
                    EndpointParameter.location == "query"
                )
                if not (await self.db.execute(p_stmt)).scalar_one_or_none():
                    self.db.add(EndpointParameter(
                        scan_id=self.scan_id,
                        asset_id=existing_asset.id,
                        name=q_name,
                        location="query",
                        value_type="string",
                        example_value=q_vals[0] if q_vals else "",
                        is_required=False
                    ))

        # 4. Extract and Persist Forms
        for form in forms:
            action = form.get("action", "")
            action_url = normalize_url(action, final_url) if action else final_url
            method = form.get("method", "GET").upper()
            
            inputs_schema = []
            is_login = False
            for inp in form.find_all(["input", "textarea", "select"]):
                itype = inp.get("type", "text").lower()
                iname = inp.get("name")
                if not iname:
                    continue
                if itype == "password" or "pass" in iname.lower():
                    is_login = True
                    has_auth_form = True

                inputs_schema.append({
                    "name": iname,
                    "type": itype,
                    "required": inp.has_attr("required"),
                    "tag": inp.name
                })

            form_type = "LOGIN" if is_login else ("SEARCH" if "q" in [i["name"] for i in inputs_schema] else "GENERAL")
            db_form = DiscoveredForm(
                scan_id=self.scan_id,
                asset_id=existing_asset.id,
                page_url=final_url,
                action=action_url,
                method=method,
                form_type=form_type,
                inputs_count=len(inputs_schema),
                inputs_schema=inputs_schema
            )
            self.db.add(db_form)

            # Also create/ensure DiscoveredAsset for Form Action target
            parsed_action = urllib.parse.urlparse(action_url)
            action_path = parsed_action.path or "/"
            fa_stmt = select(DiscoveredAsset).where(
                DiscoveredAsset.scan_id == self.scan_id,
                DiscoveredAsset.url == action_url,
                DiscoveredAsset.method == method
            )
            fa_res = await self.db.execute(fa_stmt)
            form_asset = fa_res.scalar_one_or_none()
            if not form_asset:
                form_asset = DiscoveredAsset(
                    scan_id=self.scan_id,
                    asset_type=AssetType.HTTP_ENDPOINT,
                    identifier=f"{method} {action_path}",
                    name=f"Form Action: {action_path}",
                    path=action_path,
                    url=action_url,
                    method=method,
                    discovery_status=DiscoveryStatus.RUNTIME_OBSERVED,
                    confidence=0.95,
                    metadata_json={"source": "html_form", "origin_page": final_url}
                )
                self.db.add(form_asset)
                await self.db.commit()
                await self.db.refresh(form_asset)

            # Persist Form Parameters on the Form Action Asset
            param_loc = "body" if method in ["POST", "PUT", "PATCH"] else "query"
            for inp in inputs_schema:
                fa_p_stmt = select(EndpointParameter).where(
                    EndpointParameter.scan_id == self.scan_id,
                    EndpointParameter.asset_id == form_asset.id,
                    EndpointParameter.name == inp["name"],
                    EndpointParameter.location == param_loc
                )
                if not (await self.db.execute(fa_p_stmt)).scalar_one_or_none():
                    self.db.add(EndpointParameter(
                        scan_id=self.scan_id,
                        asset_id=form_asset.id,
                        name=inp["name"],
                        location=param_loc,
                        value_type=inp.get("type", "string"),
                        is_required=inp.get("required", False)
                    ))

        if has_auth_form:
            discovered_page.has_auth_form = True

        # 5. Extract Script Bundles for JS Discovery
        for s in scripts:
            src = s.get("src")
            if src:
                script_url = normalize_url(src, final_url)
                if is_in_scope(script_url, self.target_url):
                    self.discovered_scripts.add(script_url)

        # 6. Extract Internal Links and Enqueue
        for a in links:
            href = a["href"].strip()
            # Ignore anchors and javascript: void
            if href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:"):
                continue

            link_url = normalize_url(href, final_url)
            if is_in_scope(link_url, self.target_url):
                # Clean URL of fragment
                clean_url, _ = urllib.parse.urldefrag(link_url)
                if clean_url not in self.visited_urls and depth + 1 <= self.max_depth:
                    await self.queue.put((clean_url, depth + 1))

        await self.db.commit()
