"""
JavaScript and TypeScript Route Parser for React Router, Next.js, Vue Router,
Angular, Express, and NestJS.
"""
import logging
import os
import re
from typing import List, Dict, Any, Optional

from app.scanner.discovery.source.models import (
    DiscoveredSourceRoute, SourceParameter, SourceAuthRequirement
)

logger = logging.getLogger(__name__)

# Express / Node route patterns: router.get('/users', ...), app.post('/api/login', ...)
EXPRESS_ROUTE_REGEX = re.compile(
    r'(?:app|router)\.(get|post|put|delete|patch|options|head)\s*\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE
)

# Express router prefix: app.use('/api/v1', userRouter)
EXPRESS_USE_REGEX = re.compile(
    r'app\.use\s*\(\s*["\']([^"\']+)["\']\s*,\s*([a-zA-Z0-9_]+)\s*\)'
)

# React Router JSX: <Route path="/login" element={<Login />} />
REACT_ROUTER_JSX_REGEX = re.compile(
    r'<Route[^>]*\bpath=["\']([^"\']+)["\']',
    re.IGNORECASE
)

# Object route configs (React Router createBrowserRouter, Vue Router, Angular Routes)
OBJECT_ROUTE_REGEX = re.compile(
    r'path:\s*["\']([^"\']+)["\']',
    re.IGNORECASE
)

# NestJS Controller decorator: @Controller('users') or @Controller('/api/users')
NESTJS_CONTROLLER_REGEX = re.compile(
    r'@Controller\s*\(\s*["\']?([^"\'\)]*)["\']?\s*\)'
)

# NestJS Method decorator: @Get(':id'), @Post()
NESTJS_METHOD_REGEX = re.compile(
    r'@(Get|Post|Put|Delete|Patch)\s*\(\s*["\']?([^"\'\)]*)["\']?\s*\)'
)

# Next.js App Router HTTP handlers: export async function GET(...)
NEXT_APP_ROUTER_HANDLER_REGEX = re.compile(
    r'export\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(',
    re.MULTILINE
)

class JavaScriptRouteParser:
    """
    Structured parser for frontend and backend JS/TS routes.
    """

    def __init__(self, repo_root: str):
        self.repo_root = repo_root

    def parse_file(self, file_path: str) -> List[DiscoveredSourceRoute]:
        rel_path = os.path.relpath(file_path, self.repo_root)
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            logger.debug(f"Failed to read {rel_path}: {e}")
            return []

        routes: List[DiscoveredSourceRoute] = []
        source_lines = content.splitlines()

        # -------------------------------------------------------------
        # 1. Next.js App & Pages Router (File-based Routing)
        # -------------------------------------------------------------
        norm_path = rel_path.replace("\\", "/")
        
        # Next.js App Router: app/**/page.tsx or app/**/route.ts
        if "/app/" in f"/{norm_path}" or norm_path.startswith("app/"):
            # App Router Page: frontend route
            if norm_path.endswith(("/page.tsx", "/page.jsx", "/page.js", "page.tsx", "page.jsx", "page.js")):
                page_route = self._next_app_path_to_route(norm_path, is_route_handler=False)
                routes.append(DiscoveredSourceRoute(
                    path=page_route,
                    method="GET",
                    route_type="FRONTEND",
                    framework="NEXTJS",
                    file_path=rel_path,
                    line_start=1,
                    line_end=len(source_lines),
                    handler_name="NextAppPage",
                    confidence=0.98
                ))
            # App Router API Handler: backend endpoint
            elif norm_path.endswith(("/route.ts", "/route.js", "route.ts", "route.js")):
                api_route = self._next_app_path_to_route(norm_path, is_route_handler=True)
                for match in NEXT_APP_ROUTER_HANDLER_REGEX.finditer(content):
                    method = match.group(1).upper()
                    line_num = content[:match.start()].count("\n") + 1
                    routes.append(DiscoveredSourceRoute(
                        path=api_route,
                        method=method,
                        route_type="BACKEND",
                        framework="NEXTJS",
                        file_path=rel_path,
                        line_start=line_num,
                        line_end=line_num + 5,
                        handler_name=f"export {method}",
                        confidence=0.98
                    ))

        # Next.js Pages Router: pages/**/*.tsx
        elif "/pages/" in f"/{norm_path}" or norm_path.startswith("pages/"):
            if not norm_path.endswith(("_app.tsx", "_app.js", "_document.tsx", "_document.js")):
                page_route = self._next_pages_path_to_route(norm_path)
                is_api = "/api/" in page_route
                routes.append(DiscoveredSourceRoute(
                    path=page_route,
                    method="GET" if not is_api else "ALL",
                    route_type="BACKEND" if is_api else "FRONTEND",
                    framework="NEXTJS",
                    file_path=rel_path,
                    line_start=1,
                    line_end=len(source_lines),
                    handler_name="NextPagesHandler",
                    confidence=0.95
                ))

        # -------------------------------------------------------------
        # 2. Express Route Definitions: router.get('/path', ...)
        # -------------------------------------------------------------
        for match in EXPRESS_ROUTE_REGEX.finditer(content):
            method = match.group(1).upper()
            raw_path = match.group(2)
            line_num = content[:match.start()].count("\n") + 1
            snippet = "\n".join(source_lines[max(0, line_num - 1):min(len(source_lines), line_num + 3)])

            # Normalize path: /users/:id -> /users/{id}
            clean_path = re.sub(r':([a-zA-Z0-9_]+)', r'{\1}', raw_path)
            if not clean_path.startswith("/"):
                clean_path = "/" + clean_path

            # Detect auth middleware like requireAuth, verifyToken, passport
            has_auth = any(term in snippet.lower() for term in ["auth", "jwt", "token", "protect", "passport", "guard"])

            routes.append(DiscoveredSourceRoute(
                path=clean_path,
                method=method,
                route_type="BACKEND",
                framework="EXPRESS",
                file_path=rel_path,
                line_start=line_num,
                line_end=line_num + 3,
                auth_required=has_auth,
                code_snippet=snippet,
                confidence=0.95
            ))

        # -------------------------------------------------------------
        # 3. NestJS Controllers: @Controller('prefix') + @Get('path')
        # -------------------------------------------------------------
        ctrl_match = NESTJS_CONTROLLER_REGEX.search(content)
        if ctrl_match:
            ctrl_prefix = ctrl_match.group(1).strip("/")
            base_prefix = f"/{ctrl_prefix}" if ctrl_prefix else ""

            for method_match in NESTJS_METHOD_REGEX.finditer(content):
                method = method_match.group(1).upper()
                sub_path = method_match.group(2).strip("/")
                full_path = f"{base_prefix}/{sub_path}" if sub_path else (base_prefix or "/")
                clean_path = re.sub(r':([a-zA-Z0-9_]+)', r'{\1}', full_path)

                line_num = content[:method_match.start()].count("\n") + 1
                snippet = "\n".join(source_lines[max(0, line_num - 1):min(len(source_lines), line_num + 4)])
                has_auth = any(term in snippet.lower() for term in ["authguard", "useguards", "roles", "jwt"])

                routes.append(DiscoveredSourceRoute(
                    path=clean_path,
                    method=method,
                    route_type="BACKEND",
                    framework="NESTJS",
                    file_path=rel_path,
                    line_start=line_num,
                    line_end=line_num + 4,
                    auth_required=has_auth,
                    code_snippet=snippet,
                    confidence=0.96
                ))

        # -------------------------------------------------------------
        # 4. React Router JSX Declarations: <Route path="/about" ... />
        # -------------------------------------------------------------
        for match in REACT_ROUTER_JSX_REGEX.finditer(content):
            path_val = match.group(1)
            line_num = content[:match.start()].count("\n") + 1
            snippet = "\n".join(source_lines[max(0, line_num - 1):min(len(source_lines), line_num + 2)])
            
            clean_path = re.sub(r':([a-zA-Z0-9_]+)', r'{\1}', path_val)
            if not clean_path.startswith("/"):
                clean_path = "/" + clean_path

            has_auth = any(term in snippet.lower() for term in ["protected", "requireauth", "authguard", "private"])

            routes.append(DiscoveredSourceRoute(
                path=clean_path,
                method="GET",
                route_type="FRONTEND",
                framework="REACT_ROUTER",
                file_path=rel_path,
                line_start=line_num,
                line_end=line_num + 2,
                auth_required=has_auth,
                code_snippet=snippet,
                confidence=0.92
            ))

        # -------------------------------------------------------------
        # 5. Object Route Configurations (React Router, Vue Router, Angular)
        # -------------------------------------------------------------
        # If file matches router config files (routes.ts, router.js, app-routing.module.ts)
        if any(term in norm_path.lower() for term in ["router", "routes", "routing"]):
            for match in OBJECT_ROUTE_REGEX.finditer(content):
                path_val = match.group(1)
                if path_val in ["*", ""]:
                    continue

                line_num = content[:match.start()].count("\n") + 1
                snippet = "\n".join(source_lines[max(0, line_num - 1):min(len(source_lines), line_num + 3)])
                clean_path = re.sub(r':([a-zA-Z0-9_]+)', r'{\1}', path_val)
                if not clean_path.startswith("/"):
                    clean_path = "/" + clean_path

                framework = "VUE_ROUTER" if "vue" in norm_path.lower() else ("ANGULAR" if "routing.module" in norm_path.lower() else "REACT_ROUTER")
                has_auth = any(term in snippet.lower() for term in ["canactivate", "requiresauth", "guard", "roles"])

                # Avoid duplicate if already added
                if not any(r.path == clean_path and r.line_start == line_num for r in routes):
                    routes.append(DiscoveredSourceRoute(
                        path=clean_path,
                        method="GET",
                        route_type="FRONTEND",
                        framework=framework,
                        file_path=rel_path,
                        line_start=line_num,
                        line_end=line_num + 3,
                        auth_required=has_auth,
                        code_snippet=snippet,
                        confidence=0.90
                    ))

        return routes

    def _next_app_path_to_route(self, file_path: str, is_route_handler: bool) -> str:
        # e.g. src/app/dashboard/(auth)/settings/page.tsx -> /dashboard/settings
        norm = file_path.replace("\\", "/")
        idx = norm.find("/app/")
        if idx != -1:
            segment = norm[idx + 5:]
        elif norm.startswith("app/"):
            segment = norm[4:]
        else:
            segment = norm

        # Remove trailing filename: /page.tsx or /route.ts
        parts = segment.split("/")
        parts.pop() # remove page.tsx or route.ts

        route_parts = []
        for p in parts:
            # Skip Next.js route groups like (auth)
            if p.startswith("(") and p.endswith(")"):
                continue
            # Dynamic segments: [id] -> {id}, [...slug] -> {...slug}
            if p.startswith("[") and p.endswith("]"):
                clean = p.strip("[]")
                route_parts.append(f"{{{clean}}}")
            else:
                route_parts.append(p)

        return "/" + "/".join(route_parts) if route_parts else "/"

    def _next_pages_path_to_route(self, file_path: str) -> str:
        norm = file_path.replace("\\", "/")
        idx = norm.find("/pages/")
        if idx != -1:
            segment = norm[idx + 7:]
        elif norm.startswith("pages/"):
            segment = norm[6:]
        else:
            segment = norm

        # Remove extension
        root_name = os.path.splitext(segment)[0]
        if root_name.endswith("/index") or root_name == "index":
            root_name = root_name[:-5].rstrip("/")

        parts = root_name.split("/")
        route_parts = []
        for p in parts:
            if not p:
                continue
            if p.startswith("[") and p.endswith("]"):
                clean = p.strip("[]")
                route_parts.append(f"{{{clean}}}")
            else:
                route_parts.append(p)

        return "/" + "/".join(route_parts) if route_parts else "/"
