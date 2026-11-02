import re
import logging
import urllib.parse
from typing import Set, List, Dict, Any, Optional
from app.scanner.http_client import ResilientHttpClient
from app.scanner.discovery.url_parser import is_in_scope

logger = logging.getLogger(__name__)

class JavaScriptAnalyzer:
    """
    Analyzes discovered JavaScript bundles to extract candidate frontend routes,
    API endpoints, and GraphQL operations.
    """

    # Matches URL patterns like /api/v1/users, /v2/auth/login, /api/...
    API_PATH_PATTERN = re.compile(r'["\'](/api/v[0-9]+/[a-zA-Z0-9_\-\./{}:]+|/api/[a-zA-Z0-9_\-\./{}:]+|/v[0-9]+/[a-zA-Z0-9_\-\./{}:]+)["\']')
    
    # Matches frontend routes in routers: path: "/dashboard", component: ...
    ROUTE_PATH_PATTERN = re.compile(r'path:\s*["\'](/[-a-zA-Z0-9@:%_\+.~#?&//=*{}]*)["\']')
    
    # Matches GraphQL operations: query GetUsers, mutation UpdateProfile
    GRAPHQL_PATTERN = re.compile(r'(query|mutation|subscription)\s+([A-Za-z0-9_]+)\s*[\({]')

    def __init__(self, target_base_url: str, client: ResilientHttpClient):
        self.target_base_url = target_base_url.rstrip("/")
        self.client = client
        self.analyzed_scripts: Set[str] = set()

    async def analyze_bundle(self, script_url: str) -> Dict[str, Any]:
        """Fetch and inspect a single JavaScript script file."""
        if script_url in self.analyzed_scripts:
            return {"api_paths": [], "routes": [], "graphql_ops": []}
        self.analyzed_scripts.add(script_url)

        api_paths: Set[str] = set()
        routes: Set[str] = set()
        graphql_ops: Set[str] = set()

        try:
            resp = await self.client._request("GET", script_url)
            if not resp or resp.status_code != 200:
                return {"api_paths": [], "routes": [], "graphql_ops": []}

            js_text = resp.text

            # 1. Extract API Paths
            for match in self.API_PATH_PATTERN.findall(js_text):
                # Filter out asset file extensions (.js, .css, .png, etc.)
                if not any(match.lower().endswith(ext) for ext in [".js", ".css", ".png", ".jpg", ".svg", ".woff"]):
                    api_paths.add(match)

            # 2. Extract Frontend Routes
            for match in self.ROUTE_PATH_PATTERN.findall(js_text):
                if match not in ["/", "*", ""]:
                    routes.add(match)

            # 3. Extract GraphQL Operations
            for match in self.GRAPHQL_PATTERN.findall(js_text):
                op_type, op_name = match
                graphql_ops.add(f"{op_type.upper()} {op_name}")

        except Exception as e:
            logger.debug(f"Error analyzing JavaScript bundle at {script_url}: {e}")

        return {
            "script_url": script_url,
            "api_paths": sorted(list(api_paths)),
            "routes": sorted(list(routes)),
            "graphql_ops": sorted(list(graphql_ops))
        }

    async def analyze_all(self, script_urls: List[str]) -> Dict[str, Any]:
        """Analyze a collection of discovered script URLs."""
        combined_apis: Set[str] = set()
        combined_routes: Set[str] = set()
        combined_gql: Set[str] = set()

        for s_url in script_urls:
            res = await self.analyze_bundle(s_url)
            combined_apis.update(res["api_paths"])
            combined_routes.update(res["routes"])
            combined_gql.update(res["graphql_ops"])

        logger.info(f"[JS_ANALYZER] Analyzed {len(script_urls)} bundles: found {len(combined_apis)} API paths, {len(combined_routes)} routes, {len(combined_gql)} GraphQL ops.")
        return {
            "api_paths": sorted(list(combined_apis)),
            "routes": sorted(list(combined_routes)),
            "graphql_ops": sorted(list(combined_gql))
        }
