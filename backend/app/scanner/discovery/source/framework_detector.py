"""
Framework and Language Detection from Source Code, Dependency Manifests, and Project Files.
"""
import json
import logging
import os
import re
from typing import Dict, List, Set, Tuple, Any

logger = logging.getLogger(__name__)

class SourceFrameworkDetector:
    """
    Inspects project manifests, configuration files, and source trees to identify:
    - Primary languages: Python, TypeScript, JavaScript, Java, C#, PHP, Go, Ruby, Rust
    - Frontend frameworks: React, React Router, Next.js App Router, Next.js Pages Router, Vue, Vue Router, Nuxt, Angular, Svelte, SvelteKit
    - Backend frameworks: FastAPI, Flask, Django, Express, NestJS, Laravel, Spring Boot, ASP.NET Core
    """

    @classmethod
    def detect(cls, repo_root: str) -> Dict[str, Any]:
        languages: Set[str] = set()
        frameworks: Set[str] = set()
        manifests: Dict[str, Any] = {}
        indicators: List[str] = []

        # -------------------------------------------------------------
        # 1. Inspect package.json & JS/TS lockfiles
        # -------------------------------------------------------------
        package_json_path = os.path.join(repo_root, "package.json")
        if os.path.exists(package_json_path):
            languages.add("JavaScript")
            try:
                with open(package_json_path, "r", encoding="utf-8", errors="ignore") as f:
                    pkg_data = json.load(f)
                    manifests["package.json"] = {
                        "name": pkg_data.get("name"),
                        "version": pkg_data.get("version")
                    }
                    deps = {**pkg_data.get("dependencies", {}), **pkg_data.get("devDependencies", {})}
                    
                    if "typescript" in deps or os.path.exists(os.path.join(repo_root, "tsconfig.json")):
                        languages.add("TypeScript")

                    if "react" in deps:
                        frameworks.add("React")
                    if "react-router" in deps or "react-router-dom" in deps:
                        frameworks.add("React Router")
                        frameworks.add("React")
                    if "next" in deps:
                        # Check App Router vs Pages Router convention
                        if os.path.exists(os.path.join(repo_root, "app")) or os.path.exists(os.path.join(repo_root, "src", "app")):
                            frameworks.add("Next.js App Router")
                        if os.path.exists(os.path.join(repo_root, "pages")) or os.path.exists(os.path.join(repo_root, "src", "pages")):
                            frameworks.add("Next.js Pages Router")
                        frameworks.add("Next.js")
                        frameworks.add("React")
                    if "vue" in deps:
                        frameworks.add("Vue")
                    if "vue-router" in deps:
                        frameworks.add("Vue Router")
                        frameworks.add("Vue")
                    if "nuxt" in deps or "nuxt3" in deps:
                        frameworks.add("Nuxt")
                        frameworks.add("Vue")
                    if "@angular/core" in deps:
                        frameworks.add("Angular")
                    if "svelte" in deps:
                        frameworks.add("Svelte")
                    if "@sveltejs/kit" in deps:
                        frameworks.add("SvelteKit")
                        frameworks.add("Svelte")
                    if "express" in deps:
                        frameworks.add("Express")
                    if "@nestjs/core" in deps:
                        frameworks.add("NestJS")
                        frameworks.add("Express")
            except Exception as e:
                logger.debug(f"Error parsing package.json: {e}")

        # -------------------------------------------------------------
        # 2. Inspect Python manifests (requirements.txt, pyproject.toml, Pipfile, setup.py)
        # -------------------------------------------------------------
        req_path = os.path.join(repo_root, "requirements.txt")
        if os.path.exists(req_path):
            languages.add("Python")
            manifests["requirements.txt"] = True
            try:
                with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
                    req_content = f.read().lower()
                    if "fastapi" in req_content:
                        frameworks.add("FastAPI")
                    if "flask" in req_content:
                        frameworks.add("Flask")
                    if "django" in req_content:
                        frameworks.add("Django")
                    if "djangorestframework" in req_content:
                        frameworks.add("Django")
                        frameworks.add("Django REST Framework")
            except Exception as e:
                logger.debug(f"Error reading requirements.txt: {e}")

        pyproject_path = os.path.join(repo_root, "pyproject.toml")
        if os.path.exists(pyproject_path):
            languages.add("Python")
            manifests["pyproject.toml"] = True
            try:
                with open(pyproject_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read().lower()
                    if "fastapi" in content:
                        frameworks.add("FastAPI")
                    if "flask" in content:
                        frameworks.add("Flask")
                    if "django" in content:
                        frameworks.add("Django")
            except Exception as e:
                logger.debug(f"Error reading pyproject.toml: {e}")

        # -------------------------------------------------------------
        # 3. Inspect PHP / Composer
        # -------------------------------------------------------------
        composer_path = os.path.join(repo_root, "composer.json")
        if os.path.exists(composer_path):
            languages.add("PHP")
            manifests["composer.json"] = True
            try:
                with open(composer_path, "r", encoding="utf-8", errors="ignore") as f:
                    cdata = json.load(f)
                    cdeps = {**cdata.get("require", {}), **cdata.get("require-dev", {})}
                    if "laravel/framework" in cdeps:
                        frameworks.add("Laravel")
            except Exception:
                pass

        # -------------------------------------------------------------
        # 4. Inspect Java / Maven / Gradle
        # -------------------------------------------------------------
        pom_path = os.path.join(repo_root, "pom.xml")
        gradle_path = os.path.join(repo_root, "build.gradle")
        if os.path.exists(pom_path) or os.path.exists(gradle_path):
            languages.add("Java")
            if os.path.exists(pom_path):
                manifests["pom.xml"] = True
                try:
                    with open(pom_path, "r", encoding="utf-8", errors="ignore") as f:
                        if "spring-boot" in f.read().lower():
                            frameworks.add("Spring Boot")
                except Exception:
                    pass
            if os.path.exists(gradle_path):
                manifests["build.gradle"] = True
                try:
                    with open(gradle_path, "r", encoding="utf-8", errors="ignore") as f:
                        if "spring" in f.read().lower():
                            frameworks.add("Spring Boot")
                except Exception:
                    pass

        # -------------------------------------------------------------
        # 5. File tree heuristics and source declarations
        # -------------------------------------------------------------
        for root, dirs, files in os.walk(repo_root):
            dirs[:] = [d for d in dirs if d not in [".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "target"]]
            
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext == ".py":
                    languages.add("Python")
                    if f == "manage.py" or f == "wsgi.py":
                        frameworks.add("Django")
                elif ext in [".ts", ".tsx"]:
                    languages.add("TypeScript")
                    languages.add("JavaScript")
                    if f.endswith((".controller.ts", ".module.ts", ".service.ts")):
                        frameworks.add("NestJS")
                elif ext in [".js", ".jsx"]:
                    languages.add("JavaScript")
                elif ext == ".java":
                    languages.add("Java")
                elif ext == ".php":
                    languages.add("PHP")
                elif ext == ".cs" or f.endswith(".csproj"):
                    languages.add("C#")
                    frameworks.add("ASP.NET Core")
                elif ext == ".vue":
                    frameworks.add("Vue")
                elif ext == ".svelte":
                    frameworks.add("Svelte")
                elif ext == ".go":
                    languages.add("Go")
                elif ext == ".rb":
                    languages.add("Ruby")
                elif ext == ".rs":
                    languages.add("Rust")

        return {
            "languages": sorted(list(languages)),
            "frameworks": sorted(list(frameworks)),
            "manifests": manifests
        }
