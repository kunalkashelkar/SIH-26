import re
import urllib.parse
from bs4 import BeautifulSoup
from typing import List

from .models import DiscoveredEndpoint, DiscoveredParameter
from .url_parser import normalize_url, is_in_scope

class LinkExtractor:
    API_PATTERN = re.compile(r'(/api/v[0-9]+/[a-zA-Z0-9_/-]+)')

    @staticmethod
    def extract_from_html(html_content: str, source_url: str, target_base_url: str, depth: int) -> List[DiscoveredEndpoint]:
        endpoints = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # 1. Extract standard links <a>
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            url = normalize_url(href, source_url)
            if is_in_scope(url, target_base_url):
                parsed = urllib.parse.urlparse(url)
                
                # Check for query parameters in the link
                params = []
                if parsed.query:
                    query_vars = urllib.parse.parse_qs(parsed.query)
                    for k in query_vars.keys():
                        params.append(DiscoveredParameter(name=k, location="query"))
                        
                endpoints.append(DiscoveredEndpoint(
                    url=url,
                    path=parsed.path,
                    method="GET",
                    depth=depth + 1,
                    discovered_from=source_url,
                    parameters=params
                ))

        # 2. Extract forms
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            
            url = normalize_url(action, source_url)
            if is_in_scope(url, target_base_url):
                parsed = urllib.parse.urlparse(url)
                params = []
                
                # Extract inputs
                for input_tag in form.find_all(['input', 'select', 'textarea']):
                    name = input_tag.get('name')
                    if name:
                        location = "query" if method == "GET" else "body"
                        params.append(DiscoveredParameter(name=name, location=location))

                endpoints.append(DiscoveredEndpoint(
                    url=url,
                    path=parsed.path,
                    method=method,
                    depth=depth + 1,
                    discovered_from=source_url,
                    parameters=params
                ))
                
        # 3. Quick Heuristic: extract API patterns from <script>
        for script in soup.find_all('script'):
            if script.string:
                matches = LinkExtractor.API_PATTERN.findall(script.string)
                for match in matches:
                    url = normalize_url(match, source_url)
                    if is_in_scope(url, target_base_url):
                        endpoints.append(DiscoveredEndpoint(
                            url=url,
                            path=match,
                            method="GET",
                            depth=depth + 1,
                            discovered_from=source_url,
                            is_api=True
                        ))

        return endpoints
