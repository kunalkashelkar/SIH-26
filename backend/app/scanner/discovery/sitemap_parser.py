import logging
import urllib.parse
import xml.etree.ElementTree as ET
from typing import Set, List
from app.scanner.http_client import ResilientHttpClient
from app.scanner.discovery.url_parser import is_in_scope, normalize_url

logger = logging.getLogger(__name__)

class SitemapDiscoverer:
    """
    Parses robots.txt and sitemap XML files (including nested sitemap indexes)
    to discover advertised URLs.
    """

    COMMON_SITEMAP_PATHS = [
        "/sitemap.xml",
        "/sitemap_index.xml",
        "/sitemaps.xml",
        "/sitemap-index.xml"
    ]

    def __init__(self, target_base_url: str, client: ResilientHttpClient, max_depth: int = 3):
        self.target_base_url = target_base_url.rstrip("/")
        self.client = client
        self.max_depth = max_depth
        self.discovered_urls: Set[str] = set()
        self.visited_sitemaps: Set[str] = set()

    async def discover(self) -> List[str]:
        """Execute sitemap discovery and return list of in-scope URLs."""
        sitemap_candidates: Set[str] = set()

        # 1. Inspect robots.txt for Sitemap directives
        robots_url = f"{self.target_base_url}/robots.txt"
        resp = await self.client._request("GET", robots_url)
        if resp and resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith("sitemap:"):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        sm_url = parts[1].strip()
                        if is_in_scope(sm_url, self.target_base_url):
                            sitemap_candidates.add(sm_url)

        # 2. Add common default paths
        for path in self.COMMON_SITEMAP_PATHS:
            candidate = f"{self.target_base_url}{path}"
            sitemap_candidates.add(candidate)

        # 3. Process candidate sitemaps recursively
        for sm_url in sitemap_candidates:
            await self._parse_sitemap(sm_url, current_depth=0)

        logger.info(f"Sitemap discovery found {len(self.discovered_urls)} unique URLs.")
        return sorted(list(self.discovered_urls))

    async def _parse_sitemap(self, sitemap_url: str, current_depth: int):
        if current_depth > self.max_depth or sitemap_url in self.visited_sitemaps:
            return
        self.visited_sitemaps.add(sitemap_url)

        try:
            resp = await self.client._request("GET", sitemap_url)
            if not resp or resp.status_code != 200:
                return

            text = resp.text.strip()
            if not text.startswith("<?xml") and "<urlset" not in text and "<sitemapindex" not in text:
                return

            root = ET.fromstring(text)
            # Remove namespace prefixes
            for elem in root.iter():
                if "}" in elem.tag:
                    elem.tag = elem.tag.split("}", 1)[1]

            # Nested sitemaps (<sitemap><loc>...</loc></sitemap>)
            for sitemap_tag in root.findall(".//sitemap"):
                loc = sitemap_tag.find("loc")
                if loc is not None and loc.text:
                    nested_sm = loc.text.strip()
                    if is_in_scope(nested_sm, self.target_base_url):
                        await self._parse_sitemap(nested_sm, current_depth + 1)

            # Concrete page URLs (<url><loc>...</loc></url>)
            for url_tag in root.findall(".//url"):
                loc = url_tag.find("loc")
                if loc is not None and loc.text:
                    page_url = normalize_url(loc.text.strip(), self.target_base_url)
                    if is_in_scope(page_url, self.target_base_url):
                        self.discovered_urls.add(page_url)

        except Exception as e:
            logger.debug(f"Error parsing sitemap at {sitemap_url}: {e}")
