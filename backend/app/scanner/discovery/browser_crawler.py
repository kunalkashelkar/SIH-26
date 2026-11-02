import asyncio
import logging
import urllib.parse
from typing import Set, List, Dict, Any, Optional
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.scanner.discovery.url_parser import is_in_scope, normalize_url
from app.models.discovery import (
    AssetType, DiscoveryStatus, DiscoverySource,
    DiscoveredAsset, DiscoveredPage, DiscoveredEndpoint,
    EndpointParameter, RuntimeEvidence, DiscoveryError
)

logger = logging.getLogger(__name__)

# Sensitive field patterns for redaction
REDACT_KEYS = {"password", "pass", "pwd", "secret", "token", "auth", "api_key", "apikey", "access_token"}

def sanitize_payload(data: Any) -> Any:
    """Recursively redact sensitive key values while preserving container structure."""
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            if isinstance(v, (dict, list)):
                sanitized[k] = sanitize_payload(v)
            elif any(red in k.lower() for red in REDACT_KEYS):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = v
        return sanitized
    elif isinstance(data, list):
        return [sanitize_payload(item) for item in data]
    return data

class PlaywrightDynamicCrawler:
    """
    Playwright-powered dynamic website crawler with network interception,
    JavaScript hydration, client-side route discovery, and safe interaction.
    """

    def __init__(
        self,
        scan_id: str,
        target_url: str,
        db: AsyncSession,
        max_depth: int = 2,
        max_pages: int = 50,
        custom_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[List[Dict[str, Any]]] = None
    ):
        self.scan_id = scan_id
        self.target_url = target_url.rstrip("/")
        self.db = db
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.custom_headers = custom_headers or {}
        self.auth_cookies = auth_cookies or []

        self.visited_urls: Set[str] = set()
        self.discovered_network_endpoints: Dict[str, Dict[str, Any]] = {}
        self.queue: asyncio.Queue = asyncio.Queue()

    async def run(self, cancel_event: asyncio.Event) -> Dict[str, Any]:
        """Launch headless browser and perform dynamic crawl."""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.warning("[PLAYWRIGHT] Playwright is not installed. Skipping browser crawling.")
            return {"status": "SKIPPED", "reason": "Playwright not installed"}

        logger.info(f"[PLAYWRIGHT] Starting Chromium crawler for {self.target_url} (max_pages={self.max_pages})")
        pages_crawled = 0

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]
                )

                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 CYPHER-Security-Fuzzer/2.0",
                    viewport={"width": 1280, "height": 800},
                    extra_http_headers=self.custom_headers
                )

                if self.auth_cookies:
                    await context.add_cookies(self.auth_cookies)

                page = await context.new_page()

                # Setup Network Interception
                page.on("request", self._handle_request)
                page.on("response", self._handle_response)

                await self.queue.put((self.target_url, 0))

                while not self.queue.empty() and not cancel_event.is_set():
                    if pages_crawled >= self.max_pages:
                        break

                    current_url, depth = await self.queue.get()
                    if current_url in self.visited_urls or depth > self.max_depth:
                        self.queue.task_done()
                        continue

                    self.visited_urls.add(current_url)
                    pages_crawled += 1

                    try:
                        await self._crawl_page(page, current_url, depth, cancel_event)
                    except Exception as e:
                        logger.debug(f"[PLAYWRIGHT] Page crawl error for {current_url}: {e}")
                    finally:
                        self.queue.task_done()

                await browser.close()

            # Flush intercepted network endpoints to database
            await self._flush_network_endpoints()

            logger.info(f"[PLAYWRIGHT] Dynamic crawl completed. {pages_crawled} pages rendered, {len(self.discovered_network_endpoints)} network endpoints intercepted.")
            return {
                "status": "COMPLETED",
                "pages_crawled": pages_crawled,
                "network_endpoints_captured": len(self.discovered_network_endpoints)
            }

        except Exception as e:
            logger.error(f"[PLAYWRIGHT] Browser crawler encountered error: {e}", exc_info=True)
            self.db.add(DiscoveryError(
                scan_id=self.scan_id,
                component="PLAYWRIGHT_DYNAMIC_CRAWLER",
                error_type=type(e).__name__,
                message=str(e),
                target_url=self.target_url,
                retryable=False
            ))
            await self.db.commit()
            return {"status": "FAILED", "error": str(e)}

    def _handle_request(self, request):
        """Intercept browser HTTP, fetch, XHR, and WebSocket requests."""
        url = request.url
        if not is_in_scope(url, self.target_url):
            return

        method = request.method
        res_type = request.resource_type

        # Intercept API/XHR/fetch and documents
        if res_type in ["fetch", "xhr", "websocket", "document"]:
            key = f"{method} {url}"
            if key not in self.discovered_network_endpoints:
                parsed = urllib.parse.urlparse(url)
                self.discovered_network_endpoints[key] = {
                    "url": url,
                    "path": parsed.path or "/",
                    "method": method,
                    "resource_type": res_type,
                    "query": parsed.query,
                    "post_data": sanitize_payload(request.post_data) if request.post_data else None,
                    "headers": {k: v for k, v in request.headers.items() if k.lower() not in ["cookie", "authorization"]}
                }

    def _handle_response(self, response):
        """Record status and headers from intercepted network responses."""
        url = response.url
        key = f"{response.request.method} {url}"
        if key in self.discovered_network_endpoints:
            self.discovered_network_endpoints[key]["status_code"] = response.status
            self.discovered_network_endpoints[key]["content_type"] = response.headers.get("content-type", "")

    async def _crawl_page(self, page, url: str, depth: int, cancel_event: asyncio.Event):
        """Render single page, wait for hydration, interact safely, and extract links."""
        if cancel_event.is_set():
            return

        # Navigate with bounded timeout
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=12000)
            await asyncio.sleep(0.5) # Allow microtask queue to settle
        except Exception as e:
            logger.debug(f"[PLAYWRIGHT] Navigation timeout or warning on {url}: {e}")

        # Controlled scrolling for lazy-loaded assets
        try:
            await page.evaluate("window.scrollBy(0, 800)")
            await asyncio.sleep(0.3)
        except Exception:
            pass

        # Safe interaction: click read-only tab or navigation controls
        try:
            tabs = await page.query_selector_all('[role="tab"], nav button, .tab-btn, .nav-link')
            for tab in tabs[:3]: # Limit to first 3 to prevent navigation delays
                try:
                    is_visible = await tab.is_visible()
                    if is_visible:
                        await tab.click(timeout=1000)
                        await asyncio.sleep(0.2)
                except Exception:
                    pass
        except Exception:
            pass

        # Extract rendered links
        links = await page.eval_on_selector_all(
            "a[href]",
            "elements => elements.map(e => e.getAttribute('href'))"
        )

        for href in links:
            if not href:
                continue
            href = href.strip()
            if href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:"):
                continue

            full_url = normalize_url(href, url)
            if is_in_scope(full_url, self.target_url):
                clean_url, _ = urllib.parse.urldefrag(full_url)
                if clean_url not in self.visited_urls and depth + 1 <= self.max_depth:
                    await self.queue.put((clean_url, depth + 1))

    async def _flush_network_endpoints(self):
        """Persist intercepted network traffic into DiscoveredEndpoint and RuntimeEvidence."""
        for key, data in self.discovered_network_endpoints.items():
            url = data["url"]
            path = data["path"]
            method = data["method"]
            status_code = data.get("status_code", 200)

            is_api = "/api/" in path or data.get("resource_type") in ["xhr", "fetch"]

            # 1. Create or load DiscoveredAsset
            res = await self.db.execute(
                select(DiscoveredAsset).where(
                    DiscoveredAsset.scan_id == self.scan_id,
                    DiscoveredAsset.url == url,
                    DiscoveredAsset.method == method
                )
            )
            asset = res.scalar_one_or_none()
            if not asset:
                asset = DiscoveredAsset(
                    scan_id=self.scan_id,
                    asset_type=AssetType.BACKEND_API_OPERATION if is_api else AssetType.HTTP_ENDPOINT,
                    identifier=f"{method} {path}",
                    name=path,
                    path=path,
                    url=url,
                    method=method,
                    discovery_status=DiscoveryStatus.RUNTIME_OBSERVED,
                    confidence=1.0,
                    metadata_json={"resource_type": data.get("resource_type"), "intercepted": True}
                )
                self.db.add(asset)
                await self.db.commit()
                await self.db.refresh(asset)

            # 2. Add RuntimeEvidence
            ev = RuntimeEvidence(
                scan_id=self.scan_id,
                asset_id=asset.id,
                discovery_source=DiscoverySource.PLAYWRIGHT,
                observation_type="HTTP_REQUEST" if not data.get("resource_type") == "websocket" else "WEBSOCKET_FRAME",
                url=url,
                method=method,
                response_status=status_code,
                confidence=1.0,
                verification_status=DiscoveryStatus.RUNTIME_OBSERVED,
                evidence_reference=f"Intercepted {data.get('resource_type')} traffic via Playwright"
            )
            self.db.add(ev)

            # 3. Extract Query Parameters
            if data.get("query"):
                q_vars = urllib.parse.parse_qs(data["query"])
                for q_name, q_vals in q_vars.items():
                    param_stmt = select(EndpointParameter).where(
                        EndpointParameter.scan_id == self.scan_id,
                        EndpointParameter.asset_id == asset.id,
                        EndpointParameter.name == q_name,
                        EndpointParameter.location == "query"
                    )
                    p_res = await self.db.execute(param_stmt)
                    if not p_res.scalar_one_or_none():
                        param = EndpointParameter(
                            scan_id=self.scan_id,
                            asset_id=asset.id,
                            name=q_name,
                            location="query",
                            value_type="string",
                            example_value=q_vals[0] if q_vals else ""
                        )
                        self.db.add(param)

            # 4. Extract Body Parameters from intercepted POST data
            if data.get("post_data"):
                pd = data["post_data"]
                body_dict = None
                if isinstance(pd, dict):
                    body_dict = pd
                elif isinstance(pd, str):
                    try:
                        import json
                        parsed_json = json.loads(pd)
                        if isinstance(parsed_json, dict):
                            body_dict = parsed_json
                    except Exception:
                        pass
                    if not body_dict:
                        try:
                            parsed_qs = urllib.parse.parse_qs(pd)
                            if parsed_qs:
                                body_dict = parsed_qs
                        except Exception:
                            pass
                if body_dict:
                    for b_name in body_dict.keys():
                        b_stmt = select(EndpointParameter).where(
                            EndpointParameter.scan_id == self.scan_id,
                            EndpointParameter.asset_id == asset.id,
                            EndpointParameter.name == b_name,
                            EndpointParameter.location == "body"
                        )
                        if not (await self.db.execute(b_stmt)).scalar_one_or_none():
                            self.db.add(EndpointParameter(
                                scan_id=self.scan_id,
                                asset_id=asset.id,
                                name=b_name,
                                location="body",
                                value_type="string"
                            ))

        await self.db.commit()
