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
                    for k, v in query_vars.items():
                        val = v[0] if v else ""
                        inf_type = DiscoveredParameter.infer_type(val, k)
                        params.append(DiscoveredParameter(name=k, location="query", value_type=inf_type))
                        
                is_api_endpoint = parsed.path.startswith('/api') or '/v1/' in parsed.path or '/v2/' in parsed.path
                endpoints.append(DiscoveredEndpoint(
                    url=url,
                    path=parsed.path,
                    method="GET",
                    depth=depth + 1,
                    discovered_from=source_url,
                    is_api=is_api_endpoint,
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
                    val = input_tag.get('value', '')
                    if name:
                        location = "query" if method == "GET" else "body"
                        inf_type = DiscoveredParameter.infer_type(val, name)
                        params.append(DiscoveredParameter(name=name, location=location, value_type=inf_type))

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
