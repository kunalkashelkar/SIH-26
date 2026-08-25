import asyncio
import logging
from typing import Set

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.scanner.http_client import ResilientHttpClient
from app.models.models import Endpoint, Parameter
from .robots import RobotsTxtParser
from .link_extractor import LinkExtractor
from .models import DiscoveredEndpoint

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
        """Save a discovered endpoint and its parameters to the database."""
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
        
        if endpoint_data.parameters:
            for param in endpoint_data.parameters:
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

    async def run(self, cancel_event: asyncio.Event):
        logger.info(f"Starting crawler for {self.target_url}")
        
        # 1. Fetch robots.txt
        await self.robots.fetch_and_parse(self.client)
        
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
