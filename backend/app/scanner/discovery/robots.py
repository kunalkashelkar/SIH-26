import urllib.robotparser
import urllib.parse
from app.scanner.http_client import ResilientHttpClient

class RobotsTxtParser:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.parser = urllib.robotparser.RobotFileParser()
        self.parsed = False

    async def fetch_and_parse(self, client: ResilientHttpClient):
        parsed_url = urllib.parse.urlparse(self.target_url)
        robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"
        
        resp = await client.get(robots_url)
        if resp and resp.status_code == 200:
            lines = resp.text.splitlines()
            self.parser.parse(lines)
            self.parsed = True

    def is_allowed(self, url: str) -> bool:
        if not self.parsed:
            return True # Allow by default if no robots.txt or failed to fetch
        return self.parser.can_fetch("*", url)
