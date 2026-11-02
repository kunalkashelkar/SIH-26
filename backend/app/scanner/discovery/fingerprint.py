import re
import logging
from typing import Dict, List, Set, Tuple

logger = logging.getLogger(__name__)

class TechnologyFingerprinter:
    """
    Multi-engine technology fingerprinter.
    Detects frontend and backend technologies, frameworks, and architecture paradigms.
    """

    PATTERNS = {
        # Frontend Frameworks
        "React": [
            re.compile(r'data-reactroot', re.I),
            re.compile(r'id=["\']root["\']', re.I),
            re.compile(r'react-dom', re.I),
            re.compile(r'__REACT_DEVTOOLS_GLOBAL_HOOK__'),
        ],
        "Next.js": [
            re.compile(r'__NEXT_DATA__'),
            re.compile(r'id=["\']__next["\']', re.I),
            re.compile(r'/_next/static/'),
        ],
        "Angular": [
            re.compile(r'ng-version', re.I),
            re.compile(r'<app-root', re.I),
            re.compile(r'ng-app', re.I),
            re.compile(r'zone\.js'),
        ],
        "Vue": [
            re.compile(r'data-v-[a-f0-9]+'),
            re.compile(r'__VUE__'),
            re.compile(r'vue\.runtime'),
        ],
        "Nuxt": [
            re.compile(r'__NUXT__'),
            re.compile(r'id=["\']__nuxt["\']', re.I),
            re.compile(r'/_nuxt/'),
        ],
        "Svelte": [
            re.compile(r'svelte-[a-z0-9]+'),
            re.compile(r'class=["\'][^"\']*svelte-'),
        ],
        "WordPress": [
            re.compile(r'/wp-content/'),
            re.compile(r'/wp-includes/'),
            re.compile(r'wp-json'),
            re.compile(r'name=["\']generator["\'] content=["\']WordPress', re.I),
        ],

        # Backend hints in HTML / meta
        "Django": [
            re.compile(r'csrfmiddlewaretoken'),
            re.compile(r'django', re.I),
        ],
        "Laravel": [
            re.compile(r'laravel_session', re.I),
            re.compile(r'XSRF-TOKEN'),
        ],
        "ASP.NET": [
            re.compile(r'__VIEWSTATE'),
            re.compile(r'__EVENTVALIDATION'),
        ]
    }

    HEADER_PATTERNS = {
        "Express": ["express"],
        "FastAPI": ["fastapi", "uvicorn"],
        "Flask": ["werkzeug", "flask"],
        "Django": ["django", "wsgiserver"],
        "Laravel": ["laravel"],
        "ASP.NET": ["asp.net", "iis"],
        "Spring": ["spring", "tomcat"],
    }

    @classmethod
    def fingerprint(cls, headers: Dict[str, str], html: str) -> Tuple[List[str], List[str]]:
        """
        Analyze HTTP response headers and HTML payload.
        Returns:
            (detected_technologies: List[str], architecture_tags: List[str])
        """
        detected_tech: Set[str] = set()
        architectures: Set[str] = set()

        # 1. Header Analysis
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        server = headers_lower.get("server", "")
        powered_by = headers_lower.get("x-powered-by", "")

        for tech, keywords in cls.HEADER_PATTERNS.items():
            for kw in keywords:
                if kw in server or kw in powered_by:
                    detected_tech.add(tech)

        # 2. HTML & Script Analysis
        for tech, regexes in cls.PATTERNS.items():
            for rgx in regexes:
                if rgx.search(html):
                    detected_tech.add(tech)
                    break

        # 3. Architecture Determination
        has_next = "Next.js" in detected_tech
        has_nuxt = "Nuxt" in detected_tech
        has_react = "React" in detected_tech
        has_vue = "Vue" in detected_tech
        has_angular = "Angular" in detected_tech

        if has_next or has_nuxt:
            architectures.add("SSR")
            architectures.add("SPA")
        elif has_react or has_vue or has_angular:
            # Check if root is empty (pure CSR/SPA) or has rendered content
            if re.search(r'<div id=["\'](root|app)["\']>\s*</div>', html, re.I):
                architectures.add("CSR")
                architectures.add("SPA")
            else:
                architectures.add("SSR")
                architectures.add("SPA")
        else:
            if "<script" in html.lower() and len(html) > 500:
                architectures.add("STATIC_HTML")
            else:
                architectures.add("STATIC_HTML")

        if "/api/" in html or "/graphql" in html or "axios" in html or "fetch(" in html:
            architectures.add("API_DRIVEN")

        return sorted(list(detected_tech)), sorted(list(architectures))
