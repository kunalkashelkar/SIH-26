import asyncio
import logging
import socket
import urllib.parse
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Subdomain

logger = logging.getLogger(__name__)

COMMON_SUBDOMAINS = [
    "www",
    "api",
    "admin",
    "dev",
    "test",
    "staging",
    "mail",
    "blog",
    "shop",
    "portal",
    "secure",
    "vpn",
    "internal"
]

class SubdomainDiscoverer:
    def __init__(self, scan_id: str, target_url: str, db: AsyncSession, wordlist_limit: int = 100):
        self.scan_id = scan_id
        
        # Extract base domain from target_url
        parsed = urllib.parse.urlparse(target_url)
        self.base_domain = parsed.hostname or target_url
        
        self.db = db
        self.wordlist = COMMON_SUBDOMAINS[:wordlist_limit]

    async def _resolve_subdomain(self, sub: str, cancel_event: asyncio.Event):
        if cancel_event.is_set():
            return
            
        fqdn = f"{sub}.{self.base_domain}"
        
        # In asyncio, we can use run_in_executor for getaddrinfo
        loop = asyncio.get_event_loop()
        try:
            # We just need to know if it resolves to an IP
            res = await loop.getaddrinfo(fqdn, None, family=socket.AF_INET)
            ip_addr = res[0][4][0] if res else None
            
            if ip_addr:
                from sqlalchemy.future import select
                stmt = select(Subdomain).where(
                    Subdomain.scan_id == self.scan_id,
                    Subdomain.domain == fqdn
                )
                existing = (await self.db.execute(stmt)).scalar_one_or_none()
                if not existing:
                    sub_record = Subdomain(
                        scan_id=self.scan_id,
                        domain=fqdn,
                        ip_address=ip_addr,
                        is_alive=True
                    )
                    self.db.add(sub_record)
                
        except socket.gaierror:
            # Did not resolve
            pass
        except Exception as e:
            logger.debug(f"Subdomain discovery error on {fqdn}: {e}")

    async def run(self, cancel_event: asyncio.Event):
        logger.info(f"Starting subdomain discovery on {self.base_domain} with {len(self.wordlist)} words")
        
        tasks = []
        for word in self.wordlist:
            tasks.append(self._resolve_subdomain(word, cancel_event))
            
        if tasks:
            await asyncio.gather(*tasks)
            
        await self.db.commit()
        logger.info("Subdomain discovery completed.")
