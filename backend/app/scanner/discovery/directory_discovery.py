import asyncio
import logging
import urllib.parse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.scanner.http_client import ResilientHttpClient
from app.models.models import Endpoint

logger = logging.getLogger(__name__)

# Curated wordlist to avoid huge brute-force limits
COMMON_DIRECTORIES = [
    ".git/config",
    ".env",
    "admin/",
    "administrator/",
    "api/",
    "api/v1/",
    "api/v2/",
    "backup.zip",
    "config.php",
    "test/",
    "staging/",
    "server-status"
]

class DirectoryDiscoverer:
    def __init__(self, scan_id: str, target_url: str, db: AsyncSession, 
                 client: ResilientHttpClient, wordlist_limit: int = 100):
        self.scan_id = scan_id
        self.target_url = target_url if target_url.endswith('/') else target_url + '/'
        self.db = db
        self.client = client
        self.wordlist = COMMON_DIRECTORIES[:wordlist_limit]

    async def _check_directory(self, path: str, cancel_event: asyncio.Event):
        if cancel_event.is_set():
            return
            
        url = urllib.parse.urljoin(self.target_url, path)
        try:
            resp = await self.client._request("GET", url)
            if resp and resp.status_code in [200, 401, 403]:
                norm_path = '/' + path.strip('/')
                stmt = select(Endpoint).where(
                    Endpoint.scan_id == self.scan_id,
                    Endpoint.url == url,
                    Endpoint.method == "GET"
                )
                res = await self.db.execute(stmt)
                existing = res.scalar_one_or_none()
                if not existing:
                    ep = Endpoint(
                        scan_id=self.scan_id,
                        url=url,
                        path=norm_path,
                        method="GET",
                        status_code=resp.status_code,
                        content_type=resp.headers.get("Content-Type", ""),
                        depth=1,
                        discovered_from="directory_bruteforce",
                        is_api=False
                    )
                    self.db.add(ep)
        except Exception as e:
            logger.debug(f"Dir discovery error on {url}: {e}")

    async def run(self, cancel_event: asyncio.Event):
        logger.info(f"Starting directory discovery on {self.target_url} with {len(self.wordlist)} words")
        
        tasks = []
        for word in self.wordlist:
            tasks.append(self._check_directory(word, cancel_event))
            
        # Run batches concurrently (resilient client handles concurrency limits)
        if tasks:
            await asyncio.gather(*tasks)
            
        await self.db.commit()
        logger.info("Directory discovery completed.")
