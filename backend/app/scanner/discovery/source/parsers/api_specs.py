"""
Static API Specification Parser for OpenAPI, Swagger, Postman Collections, and GraphQL.
"""
import json
import logging
import os
import re
from typing import List, Dict, Any, Optional

try:
    import yaml
except ImportError:
    yaml = None

from app.scanner.discovery.source.models import DiscoveredSourceRoute, SourceParameter

logger = logging.getLogger(__name__)

SPEC_FILENAMES = {
    "openapi.json", "openapi.yaml", "openapi.yml",
    "swagger.json", "swagger.yaml", "swagger.yml",
    "api-spec.json", "api-spec.yaml"
}

class StaticApiSpecParser:
    """
    Finds and parses API specification files stored directly inside repository directories.
    """

    def __init__(self, repo_root: str):
        self.repo_root = repo_root

    def parse_repository(self) -> List[DiscoveredSourceRoute]:
        discovered_routes: List[DiscoveredSourceRoute] = []

        for root, dirs, files in os.walk(self.repo_root):
            # Skip caches
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ["node_modules", ".venv", "dist", "build"]]

            for f in files:
                f_lower = f.lower()
                full_path = os.path.join(root, f)

                # 1. OpenAPI / Swagger files
                if f_lower in SPEC_FILENAMES:
                    ops = self._parse_openapi_file(full_path)
                    discovered_routes.extend(ops)

                # 2. Postman Collection
                elif f_lower.endswith(".postman_collection.json"):
                    ops = self._parse_postman_collection(full_path)
                    discovered_routes.extend(ops)

                # 3. GraphQL Schema
                elif f_lower.endswith((".graphql", ".gql")) or f_lower == "schema.graphql":
                    ops = self._parse_graphql_file(full_path)
                    discovered_routes.extend(ops)

        return discovered_routes

    def _parse_openapi_file(self, file_path: str) -> List[DiscoveredSourceRoute]:
        rel_path = os.path.relpath(file_path, self.repo_root)
        routes: List[DiscoveredSourceRoute] = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
                if file_path.endswith(".json"):
                    spec = json.load(fp)
                elif yaml:
                    spec = yaml.safe_load(fp)
                else:
                    return []
        except Exception as e:
            logger.debug(f"Failed to parse OpenAPI spec at {rel_path}: {e}")
            return []

        if not isinstance(spec, dict) or "paths" not in spec:
            return []

        for path, path_item in spec.get("paths", {}).items():
            if not isinstance(path_item, dict):
                continue

            for method, details in path_item.items():
                method_upper = method.upper()
                if method_upper not in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]:
                    continue

                if not isinstance(details, dict):
                    continue

                params: List[SourceParameter] = []
                for p in details.get("parameters", []):
                    if isinstance(p, dict):
                        p_name = p.get("name")
                        p_loc = p.get("in", "query")
                        p_type = p.get("schema", {}).get("type", "string") if isinstance(p.get("schema"), dict) else "string"
                        p_req = p.get("required", False)
                        if p_name:
                            params.append(SourceParameter(
                                name=p_name,
                                location=p_loc,
                                value_type=p_type,
                                is_required=p_req
                            ))

                clean_path = path if path.startswith("/") else f"/{path}"
                routes.append(DiscoveredSourceRoute(
                    path=clean_path,
                    method=method_upper,
                    route_type="BACKEND",
                    framework="OPENAPI_SPEC",
                    file_path=rel_path,
                    line_start=1,
                    line_end=1,
                    handler_name=details.get("operationId", "openApiOp"),
                    parameters=params,
                    confidence=0.98,
                    metadata={"summary": details.get("summary", "")}
                ))

        return routes

    def _parse_postman_collection(self, file_path: str) -> List[DiscoveredSourceRoute]:
        rel_path = os.path.relpath(file_path, self.repo_root)
        routes: List[DiscoveredSourceRoute] = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
                data = json.load(fp)
        except Exception:
            return []

        items = data.get("item", [])
        self._extract_postman_items(items, rel_path, routes)
        return routes

    def _extract_postman_items(self, items: List[Dict[str, Any]], rel_path: str, routes: List[DiscoveredSourceRoute]):
        for it in items:
            if "item" in it:
                self._extract_postman_items(it["item"], rel_path, routes)
            elif "request" in it:
                req = it["request"]
                method = req.get("method", "GET").upper()
                url_obj = req.get("url", {})
                
                raw_url = ""
                if isinstance(url_obj, str):
                    raw_url = url_obj
                elif isinstance(url_obj, dict):
                    raw_url = url_obj.get("raw", "")
                    if not raw_url and "path" in url_obj:
                        path_segments = url_obj["path"]
                        if isinstance(path_segments, list):
                            raw_url = "/" + "/".join(str(s) for s in path_segments)

                if raw_url:
                    # Clean host prefix if present
                    if "://" in raw_url:
                        import urllib.parse
                        p = urllib.parse.urlparse(raw_url)
                        raw_url = p.path or "/"

                    routes.append(DiscoveredSourceRoute(
                        path=raw_url,
                        method=method,
                        route_type="BACKEND",
                        framework="POSTMAN_COLLECTION",
                        file_path=rel_path,
                        line_start=1,
                        line_end=1,
                        handler_name=it.get("name", "postman_request"),
                        confidence=0.92
                    ))

    def _parse_graphql_file(self, file_path: str) -> List[DiscoveredSourceRoute]:
        rel_path = os.path.relpath(file_path, self.repo_root)
        routes: List[DiscoveredSourceRoute] = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
                content = fp.read()
        except Exception:
            return []

        # Find query/mutation fields in type Query { ... } or type Mutation { ... }
        type_matches = re.finditer(r'type\s+(Query|Mutation)\s*\{([^}]+)\}', content, re.MULTILINE)
        for tm in type_matches:
            op_type = tm.group(1).upper()
            body = tm.group(2)
            for line in body.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                field_match = re.match(r'([a-zA-Z0-9_]+)\s*(?:\([^)]*\))?\s*:', line)
                if field_match:
                    field_name = field_match.group(1)
                    routes.append(DiscoveredSourceRoute(
                        path=f"/graphql?op={field_name}",
                        method="POST",
                        route_type="BACKEND",
                        framework="GRAPHQL",
                        file_path=rel_path,
                        line_start=1,
                        line_end=1,
                        handler_name=f"{op_type} {field_name}",
                        confidence=0.90
                    ))

        return routes
