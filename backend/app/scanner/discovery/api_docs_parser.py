import logging
import urllib.parse
from typing import List, Dict, Any, Optional
from app.scanner.http_client import ResilientHttpClient
from app.scanner.discovery.models import DiscoveredEndpoint, DiscoveredParameter

logger = logging.getLogger(__name__)

class ApiDocsParser:
    """
    Discovers and parses OpenAPI, Swagger, and API documentation endpoints.
    """

    CANDIDATE_PATHS = [
        "/openapi.json",
        "/swagger.json",
        "/api-docs",
        "/api/openapi.json",
        "/v3/api-docs",
        "/v2/api-docs",
        "/api/v1/openapi.json"
    ]

    def __init__(self, target_base_url: str, client: ResilientHttpClient):
        self.target_base_url = target_base_url.rstrip("/")
        self.client = client

    async def discover_and_parse(self) -> List[Dict[str, Any]]:
        """Probe common OpenAPI specification paths and return extracted operations."""
        operations = []

        for path in self.CANDIDATE_PATHS:
            url = f"{self.target_base_url}{path}"
            resp = await self.client._request("GET", url)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, dict) and "paths" in data:
                        logger.info(f"[API_DOCS] Discovered OpenAPI specification at: {url}")
                        parsed_ops = self._parse_openapi_dict(data, url)
                        operations.extend(parsed_ops)
                        break # Stop after finding primary OpenAPI spec
                except Exception as e:
                    logger.debug(f"[API_DOCS] JSON parse error for {url}: {e}")

        return operations

    def _parse_openapi_dict(self, spec: Dict[str, Any], doc_url: str) -> List[Dict[str, Any]]:
        operations = []
        paths = spec.get("paths", {})

        for path_pattern, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            for method, details in path_item.items():
                method_upper = method.upper()
                if method_upper not in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]:
                    continue

                if not isinstance(details, dict):
                    continue

                parameters = []
                # 1. Parse parameters
                for p in details.get("parameters", []):
                    if isinstance(p, dict):
                        p_name = p.get("name")
                        p_loc = p.get("in", "query")
                        p_type = p.get("schema", {}).get("type", "string") if isinstance(p.get("schema"), dict) else "string"
                        p_req = p.get("required", False)
                        if p_name:
                            parameters.append({
                                "name": p_name,
                                "location": p_loc,
                                "value_type": p_type,
                                "is_required": p_req
                            })

                # 2. Parse requestBody (OpenAPI 3.0)
                body_schema = None
                req_body = details.get("requestBody")
                if isinstance(req_body, dict):
                    content = req_body.get("content", {})
                    if "application/json" in content:
                        body_schema = content["application/json"].get("schema")

                full_url = urllib.parse.urljoin(self.target_base_url + "/", path_pattern.lstrip("/"))
                operations.append({
                    "url": full_url,
                    "path": path_pattern,
                    "method": method_upper,
                    "operation_id": details.get("operationId"),
                    "summary": details.get("summary", ""),
                    "parameters": parameters,
                    "body_schema": body_schema,
                    "doc_url": doc_url
                })

        return operations
