"""
Python AST Route Parser for FastAPI, Flask, and Pydantic Schemas.
Analyzes source code via Python's native AST module without executing any code.
"""
import ast
import logging
import os
import re
from typing import List, Dict, Any, Optional, Tuple

from app.scanner.discovery.source.models import (
    DiscoveredSourceRoute, SourceParameter, SourceAuthRequirement
)

logger = logging.getLogger(__name__)

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}

class PythonRouteParser:
    """
    AST-based parser for FastAPI and Flask route definitions.
    Extracts paths, HTTP methods, prefixes, parameters, Pydantic body models,
    and auth dependencies.
    """

    def __init__(self, repo_root: str):
        self.repo_root = repo_root

    def parse_file(self, file_path: str) -> List[DiscoveredSourceRoute]:
        """Parse a Python source file using ast."""
        rel_path = os.path.relpath(file_path, self.repo_root)
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                source_code = f.read()
            tree = ast.parse(source_code, filename=file_path)
        except Exception as e:
            logger.debug(f"AST parse failed for {rel_path}: {e}")
            return []

        source_lines = source_code.splitlines()

        # 1. Identify Routers and Prefixes
        router_prefixes: Dict[str, str] = {}
        # Track include_router calls: {router_var: prefix}
        included_prefixes: Dict[str, str] = {}

        for node in ast.walk(tree):
            # router = APIRouter(prefix="/api/v1") or bp = Blueprint('...', url_prefix='/...')
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Call):
                    func_name = self._get_call_name(node.value.func)
                    if func_name in ["APIRouter", "Blueprint"]:
                        prefix = self._extract_kwarg_str(node.value, "prefix") or self._extract_kwarg_str(node.value, "url_prefix") or ""
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                router_prefixes[target.id] = prefix

            # app.include_router(router, prefix="/api")
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                func_name = self._get_call_name(node.value.func)
                if func_name and func_name.endswith("include_router"):
                    if node.value.args and isinstance(node.value.args[0], ast.Name):
                        r_var = node.value.args[0].id
                        inc_prefix = self._extract_kwarg_str(node.value, "prefix") or ""
                        included_prefixes[r_var] = inc_prefix

        # 2. Extract Route Functions
        routes: List[DiscoveredSourceRoute] = []

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                route_decorators = self._find_route_decorators(node, router_prefixes, included_prefixes)
                for dec in route_decorators:
                    method = dec["method"].upper()
                    path = dec["path"]
                    framework = dec["framework"]
                    router_name = dec["router_name"]

                    # Extract function parameters & auth dependencies
                    params, auth_req = self._extract_parameters_and_auth(node)

                    # Extract line range & snippet
                    start_line = node.lineno
                    end_line = getattr(node, "end_lineno", start_line + 5)
                    snippet = "\n".join(source_lines[start_line - 1:min(end_line, len(source_lines))])

                    discovered = DiscoveredSourceRoute(
                        path=path,
                        method=method,
                        route_type="BACKEND",
                        framework=framework,
                        file_path=rel_path,
                        line_start=start_line,
                        line_end=end_line,
                        handler_name=node.name,
                        auth_required=auth_req is not None,
                        auth_details=auth_req,
                        parameters=params,
                        code_snippet=snippet[:500],
                        confidence=0.95,
                        metadata={"router_var": router_name}
                    )
                    routes.append(discovered)

        return routes

    def _find_route_decorators(
        self,
        node: ast.FunctionDef,
        router_prefixes: Dict[str, str],
        included_prefixes: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """Identify @app.get, @router.post, @bp.route decorators."""
        results = []
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue

            dec_name = self._get_call_name(decorator.func)
            if not dec_name:
                continue

            parts = dec_name.split(".")
            if len(parts) != 2:
                continue

            router_var, action = parts[0], parts[1].lower()

            # FastAPI: @app.get('/path'), @router.post('/path')
            if action in HTTP_METHODS:
                raw_path = self._extract_first_arg_str(decorator) or "/"
                prefix = router_prefixes.get(router_var, "")
                inc_prefix = included_prefixes.get(router_var, "")
                full_path = self._join_paths(inc_prefix, prefix, raw_path)
                results.append({
                    "method": action,
                    "path": full_path,
                    "framework": "FASTAPI",
                    "router_name": router_var
                })

            # Flask: @app.route('/path', methods=['GET', 'POST'])
            elif action == "route":
                raw_path = self._extract_first_arg_str(decorator) or "/"
                prefix = router_prefixes.get(router_var, "")
                methods = self._extract_flask_methods(decorator) or ["GET"]
                for m in methods:
                    results.append({
                        "method": m,
                        "path": self._join_paths(prefix, raw_path),
                        "framework": "FLASK",
                        "router_name": router_var
                    })

        return results

    def _extract_parameters_and_auth(
        self,
        node: ast.FunctionDef
    ) -> Tuple[List[SourceParameter], Optional[SourceAuthRequirement]]:
        """Inspect function signature arguments for path, query, body, and auth dependencies."""
        params: List[SourceParameter] = []
        auth_req: Optional[SourceAuthRequirement] = None

        for arg in node.args.args:
            name = arg.arg
            if name in ["self", "cls"]:
                continue

            arg_type = "string"
            if arg.annotation:
                arg_type = self._ast_to_str(arg.annotation)

            # Check defaults (e.g. Depends(get_current_user), Query(...), Body(...))
            default_val = None
            is_dep = False

            # Check if this parameter corresponds to a default
            # Defaults are aligned to the right of args
            num_args = len(node.args.args)
            num_defaults = len(node.args.defaults)
            diff = num_args - num_defaults
            arg_idx = node.args.args.index(arg)

            if arg_idx >= diff:
                default_node = node.args.defaults[arg_idx - diff]
                default_val_str = self._ast_to_str(default_node)
                
                # Check for FastAPI Depends / Security authentication
                if "Depends" in default_val_str or "Security" in default_val_str:
                    is_dep = True
                    dep_name = default_val_str.lower()
                    if any(term in dep_name for term in ["auth", "user", "token", "login", "jwt", "permission"]):
                        auth_req = SourceAuthRequirement(
                            auth_type="JWT" if "jwt" in dep_name else "BEARER",
                            mechanism=default_val_str,
                            is_enforced=True,
                            line_number=node.lineno
                        )

            if not is_dep:
                loc = "body" if any(t in arg_type for t in ["Model", "Schema", "Create", "Update", "Request", "Dict", "dict"]) else "query"
                params.append(SourceParameter(
                    name=name,
                    location=loc,
                    value_type=arg_type,
                    is_required=(arg_idx < diff)
                ))

        return params, auth_req

    def _extract_flask_methods(self, call_node: ast.Call) -> List[str]:
        for kw in call_node.keywords:
            if kw.arg == "methods":
                if isinstance(kw.value, (ast.List, ast.Tuple)):
                    methods = []
                    for el in kw.value.elts:
                        if isinstance(el, ast.Constant) and isinstance(el.value, str):
                            methods.append(el.value.upper())
                    return methods
        return ["GET"]

    def _extract_first_arg_str(self, call_node: ast.Call) -> Optional[str]:
        if call_node.args and isinstance(call_node.args[0], ast.Constant) and isinstance(call_node.args[0].value, str):
            return call_node.args[0].value
        return None

    def _extract_kwarg_str(self, call_node: ast.Call, kwarg_name: str) -> Optional[str]:
        for kw in call_node.keywords:
            if kw.arg == kwarg_name and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                return kw.value.value
        return None

    def _get_call_name(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._get_call_name(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        return None

    def _ast_to_str(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Constant):
            return str(node.value)
        elif isinstance(node, ast.Attribute):
            return f"{self._ast_to_str(node.value)}.{node.attr}"
        elif isinstance(node, ast.Call):
            func_name = self._ast_to_str(node.func)
            arg_strs = [self._ast_to_str(a) for a in node.args]
            return f"{func_name}({', '.join(arg_strs)})"
        elif isinstance(node, ast.Subscript):
            return f"{self._ast_to_str(node.value)}[{self._ast_to_str(node.slice)}]"
        return "any"

    def _join_paths(self, *parts: str) -> str:
        clean_parts = [p.strip("/") for p in parts if p and p.strip("/")]
        return "/" + "/".join(clean_parts) if clean_parts else "/"
