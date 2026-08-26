import asyncio
import logging
import urllib.parse
from typing import Set

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.scanner.http_client import ResilientHttpClient
from app.models.models import Endpoint, Parameter
from .robots import RobotsTxtParser
from .link_extractor import LinkExtractor
from .models import DiscoveredEndpoint, DiscoveredParameter

logger = logging.getLogger(__name__)

class AsyncCrawler:
    def __init__(self, scan_id: str, target_url: str, db: AsyncSession, 
                 client: ResilientHttpClient, max_depth: int = 3):
        self.scan_id = scan_id
        self.target_url = target_url
        self.db = db
        self.client = client
        self.max_depth = max_depth
        
        self.visited_urls: Set[str] = set()
        self.queue = asyncio.Queue()
        self.robots = RobotsTxtParser(target_url)

    async def flush_to_db(self, endpoint_data: DiscoveredEndpoint):
        """Save a discovered endpoint and its parameters to the database without duplicates."""
        stmt = select(Endpoint).where(
            Endpoint.scan_id == self.scan_id,
            Endpoint.url == endpoint_data.url,
            Endpoint.method == endpoint_data.method
        )
        res = await self.db.execute(stmt)
        db_endpoint = res.scalar_one_or_none()

        if not db_endpoint:
            db_endpoint = Endpoint(
                scan_id=self.scan_id,
                url=endpoint_data.url,
                path=endpoint_data.path,
                method=endpoint_data.method,
                status_code=endpoint_data.status_code,
                content_type=endpoint_data.content_type,
                depth=endpoint_data.depth,
                discovered_from=endpoint_data.discovered_from,
                is_api=endpoint_data.is_api
            )
            self.db.add(db_endpoint)
            await self.db.commit()
            await self.db.refresh(db_endpoint)
        else:
            # Update attributes if discovered later with more detail
            if endpoint_data.status_code and not db_endpoint.status_code:
                db_endpoint.status_code = endpoint_data.status_code
            if endpoint_data.content_type and not db_endpoint.content_type:
                db_endpoint.content_type = endpoint_data.content_type
            if endpoint_data.is_api:
                db_endpoint.is_api = True
            await self.db.commit()
        
        if endpoint_data.parameters:
            for param in endpoint_data.parameters:
                p_stmt = select(Parameter).where(
                    Parameter.endpoint_id == db_endpoint.id,
                    Parameter.name == param.name,
                    Parameter.location == param.location
                )
                p_res = await self.db.execute(p_stmt)
                existing_p = p_res.scalar_one_or_none()
                if not existing_p:
                    db_param = Parameter(
                        endpoint_id=db_endpoint.id,
                        name=param.name,
                        location=param.location,
                        value_type=param.value_type
                    )
                    self.db.add(db_param)
            await self.db.commit()

    async def process_url(self, endpoint: DiscoveredEndpoint, cancel_event: asyncio.Event):
        if cancel_event.is_set():
            return

        if endpoint.url in self.visited_urls:
            return
            
        if not self.robots.is_allowed(endpoint.url):
            logger.info(f"Skipping {endpoint.url} (disallowed by robots.txt)")
            return

        if endpoint.depth > self.max_depth:
            return

        self.visited_urls.add(endpoint.url)
        logger.info(f"Crawling: {endpoint.method} {endpoint.url} (Depth: {endpoint.depth})")

        # Fetch
        resp = await self.client._request(endpoint.method, endpoint.url)
        if resp:
            endpoint.status_code = resp.status_code
            endpoint.content_type = resp.headers.get("Content-Type", "")
            
            # Save to DB
            await self.flush_to_db(endpoint)
            
            # If HTML, extract links and enqueue
            if "text/html" in endpoint.content_type.lower():
                extracted = LinkExtractor.extract_from_html(resp.text, endpoint.url, self.target_url, endpoint.depth)
                for ext_ep in extracted:
                    if ext_ep.url not in self.visited_urls:
                        await self.queue.put(ext_ep)
            elif "application/json" in endpoint.content_type.lower() or endpoint.path.endswith('.json'):
                try:
                    data = resp.json()
                    if isinstance(data, dict) and "paths" in data:
                        for path, methods in data["paths"].items():
                            if isinstance(methods, dict):
                                for method, details in methods.items():
                                    if method.lower() not in ["get", "post", "put", "delete", "patch", "options", "head"]:
                                        continue
                                    params = []
                                    if isinstance(details, dict):
                                        for param in details.get("parameters", []):
                                            if isinstance(param, dict):
                                                name = param.get("name")
                                                loc = param.get("in", "query")
                                                ptype = param.get("schema", {}).get("type", "string") if isinstance(param.get("schema"), dict) else "string"
                                                if ptype == "integer": ptype = "numeric"
                                                if name:
                                                    params.append(DiscoveredParameter(name=name, location=loc, value_type=ptype))
                                    
                                    norm_path = '/' + path.lstrip('/')
                                    ep_url = urllib.parse.urljoin(self.target_url if self.target_url.endswith('/') else self.target_url + '/', path.lstrip('/'))
                                    ep = DiscoveredEndpoint(
                                        url=ep_url, path=norm_path, method=method.upper(), depth=endpoint.depth + 1,
                                        discovered_from=endpoint.url, is_api=True, parameters=params
                                    )
                                    logger.info(f"OpenAPI spec parsed endpoint: {method.upper()} {norm_path} ({len(params)} params)")
                                    await self.flush_to_db(ep)
                except Exception as e:
                    logger.error(f"JSON parsing error for {endpoint.url}: {e}", exc_info=True)

    async def fetch_openapi(self):
        """Attempt to fetch OpenAPI definition to extract API parameters."""
        paths = ["/openapi.json", "/swagger.json", "/api-docs", "/api/openapi.json", "/v3/api-docs", "/v2/api-docs"]
        for p in paths:
            url = urllib.parse.urljoin(self.target_url if self.target_url.endswith('/') else self.target_url + '/', p.lstrip('/'))
            logger.info(f"Attempting OpenAPI discovery at: {url}")
            resp = await self.client._request("GET", url)
            logger.info(f"OpenAPI check {url} returned status: {resp.status_code if resp else 'None'}")
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, dict) and "paths" in data:
                        logger.info(f"Discovered OpenAPI spec at {url} with {len(data['paths'])} endpoints")
                        for path, methods in data["paths"].items():
                            if isinstance(methods, dict):
                                for method, details in methods.items():
                                    if method.lower() not in ["get", "post", "put", "delete", "patch", "options", "head"]:
                                        continue
                                    params = []
                                    if isinstance(details, dict):
                                        for param in details.get("parameters", []):
                                            if isinstance(param, dict):
                                                name = param.get("name")
                                                loc = param.get("in", "query")
                                                ptype = param.get("schema", {}).get("type", "string") if isinstance(param.get("schema"), dict) else "string"
                                                if ptype == "integer": ptype = "numeric"
                                                if name:
                                                    params.append(DiscoveredParameter(name=name, location=loc, value_type=ptype))
                                    
                                    norm_path = '/' + path.lstrip('/')
                                    ep_url = urllib.parse.urljoin(self.target_url if self.target_url.endswith('/') else self.target_url + '/', path.lstrip('/'))
                                    ep = DiscoveredEndpoint(
                                        url=ep_url, path=norm_path, method=method.upper(), depth=1,
                                        discovered_from=url, is_api=True, parameters=params
                                    )
                                    self.visited_urls.add(ep_url)
                                    await self.flush_to_db(ep)
                        return # stop after first successful OpenAPI doc
                except Exception as e:
                    import traceback
                    logger.error(f"Error parsing OpenAPI at {url}: {e}\n{traceback.format_exc()}")

    async def run(self, cancel_event: asyncio.Event):
        logger.info(f"Starting crawler for {self.target_url}")
        
        # 1. Fetch robots.txt
        await self.robots.fetch_and_parse(self.client)
        
        # 1.5 Fetch OpenAPI
        await self.fetch_openapi()
        
        # 2. Enqueue root URL
        root_endpoint = DiscoveredEndpoint(
            url=self.target_url,
            path="/",
            method="GET",
            depth=0
        )
        await self.queue.put(root_endpoint)
        
        # 3. Process Queue
        # We will use a set of worker tasks to process the queue concurrently
        # The queue.get() will block until an item is available.
        # We must detect when the queue is empty AND all tasks are idle.
        
        active_tasks = 0
        
        while not cancel_event.is_set():
            # If queue is empty and no active tasks, we are done
            if self.queue.empty() and active_tasks == 0:
                break
                
            try:
                # Wait for next item with timeout
                endpoint = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                active_tasks += 1
                
                try:
                    await self.process_url(endpoint, cancel_event)
                except Exception as e:
                    logger.error(f"Crawler error on {endpoint.url}: {e}")
                finally:
                    self.queue.task_done()
                    active_tasks -= 1
                    
            except asyncio.TimeoutError:
                # Loop around to check condition
                continue

        logger.info(f"Crawler finished. Visited {len(self.visited_urls)} URLs.")
