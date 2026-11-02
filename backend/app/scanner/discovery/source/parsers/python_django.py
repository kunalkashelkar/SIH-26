"""
Python AST Route Parser for Django and Django REST Framework (DRF).
"""
import ast
import logging
import os
import re
from typing import List, Dict, Any, Optional

from app.scanner.discovery.source.models import (
    DiscoveredSourceRoute, SourceParameter, SourceAuthRequirement
)

logger = logging.getLogger(__name__)

class DjangoRouteParser:
    """
    Parses Django urls.py files and DRF ViewSet router registrations.
    """

    def __init__(self, repo_root: str):
        self.repo_root = repo_root

    def parse_file(self, file_path: str) -> List[DiscoveredSourceRoute]:
        """Parse Django urls.py."""
        rel_path = os.path.relpath(file_path, self.repo_root)
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                source_code = f.read()
            tree = ast.parse(source_code, filename=file_path)
        except Exception as e:
            logger.debug(f"Django AST parse failed for {rel_path}: {e}")
            return []

        source_lines = source_code.splitlines()
        routes: List[DiscoveredSourceRoute] = []

        for node in ast.walk(tree):
            # urlpatterns = [ path('api/users/', views.user_list), ... ]
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "urlpatterns":
                        if isinstance(node.value, (ast.List, ast.Tuple)):
                            for elt in node.value.elts:
                                if isinstance(elt, ast.Call):
                                    func_name = self._get_name(elt.func)
                                    if func_name in ["path", "re_path", "url"]:
                                        extracted = self._parse_path_call(elt, rel_path, source_lines)
                                        if extracted:
                                            routes.extend(extracted)

            # DRF router: router.register(r'products', ProductViewSet)
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                func_name = self._get_name(node.value.func)
                if func_name and func_name.endswith("register"):
                    drf_routes = self._parse_drf_register(node.value, rel_path, source_lines)
                    routes.extend(drf_routes)

        return routes

    def _parse_path_call(self, call_node: ast.Call, rel_path: str, source_lines: List[str]) -> List[DiscoveredSourceRoute]:
        if not call_node.args:
            return []
        
        path_pattern = ""
        first_arg = call_node.args[0]
        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
            path_pattern = first_arg.value
        
        if not path_pattern.startswith("/"):
            path_pattern = "/" + path_pattern

        handler_name = "django_view"
        if len(call_node.args) > 1:
            handler_name = self._get_name(call_node.args[1]) or "view"

        start_line = call_node.lineno
        end_line = getattr(call_node, "end_lineno", start_line)
        snippet = "\n".join(source_lines[start_line - 1:min(end_line, len(source_lines))])

        # Convert django <int:id> to {id}
        clean_path = re.sub(r'<([a-zA-Z0-9_]+:)?([a-zA-Z0-9_]+)>', r'{\2}', path_pattern)

        # Standard Django view defaults to GET/POST
        return [
            DiscoveredSourceRoute(
                path=clean_path,
                method="GET",
                route_type="BACKEND",
                framework="DJANGO",
                file_path=rel_path,
                line_start=start_line,
                line_end=end_line,
                handler_name=handler_name,
                code_snippet=snippet,
                confidence=0.90
            )
        ]

    def _parse_drf_register(self, call_node: ast.Call, rel_path: str, source_lines: List[str]) -> List[DiscoveredSourceRoute]:
        """Expands DRF ViewSet registrations into standard REST actions."""
        if not call_node.args:
            return []
        prefix = ""
        if isinstance(call_node.args[0], ast.Constant) and isinstance(call_node.args[0].value, str):
            prefix = call_node.args[0].value.strip("/")
        
        viewset_name = "DRFViewSet"
        if len(call_node.args) > 1:
            viewset_name = self._get_name(call_node.args[1]) or viewset_name

        start_line = call_node.lineno
        end_line = getattr(call_node, "end_lineno", start_line)
        snippet = "\n".join(source_lines[start_line - 1:min(end_line, len(source_lines))])

        base_path = f"/{prefix}"
        item_path = f"/{prefix}/{{id}}"

        drf_ops = [
            ("GET", base_path, f"{viewset_name}.list"),
            ("POST", base_path, f"{viewset_name}.create"),
            ("GET", item_path, f"{viewset_name}.retrieve"),
            ("PUT", item_path, f"{viewset_name}.update"),
            ("DELETE", item_path, f"{viewset_name}.destroy"),
        ]

        results = []
        for method, path, handler in drf_ops:
            results.append(DiscoveredSourceRoute(
                path=path,
                method=method,
                route_type="BACKEND",
                framework="DJANGO_REST_FRAMEWORK",
                file_path=rel_path,
                line_start=start_line,
                line_end=end_line,
                handler_name=handler,
                code_snippet=snippet,
                confidence=0.92
            ))
        return results

    def _get_name(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._get_name(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        return None
