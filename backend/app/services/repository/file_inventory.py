"""
Source File Inventory Builder.
Categorizes repository files, determines eligibility, detects languages, and records exclusions.
"""
import os
import logging
from typing import Dict, List, Tuple

from app.services.repository.repository_models import SourceFileEntry, FileInventorySummary

logger = logging.getLogger(__name__)

EXCLUDED_DIR_NAMES = {
    "node_modules", ".git", "dist", "build", "coverage", ".nyc_output",
    "vendor", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".idea", ".vscode", "target", "bin", "obj", ".next", ".nuxt", ".svelte-kit"
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".bmp",
    ".mp4", ".mp3", ".wav", ".avi", ".mov", ".flv",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".class", ".pyc"
}

EXTENSION_TO_LANGUAGE = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".vue": "Vue",
    ".svelte": "Svelte",
    ".java": "Java",
    ".cs": "C#",
    ".php": "PHP",
    ".go": "Go",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".c": "C",
    ".cpp": "C++",
    ".h": "C/C++ Header",
    ".hpp": "C++ Header",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".sass": "SASS",
    ".less": "LESS",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".xml": "XML",
    ".sql": "SQL",
    ".graphql": "GraphQL",
    ".gql": "GraphQL",
    ".proto": "Protocol Buffers",
    ".md": "Markdown",
    ".env": "Config",
    ".toml": "TOML",
    ".ini": "INI",
    ".properties": "Properties"
}

class FileInventoryBuilder:
    """
    Scans an extracted repository workspace and constructs a full inventory of source files.
    """

    def __init__(self, repo_root: str, max_files: int = 10000, max_file_size_bytes: int = 10 * 1024 * 1024):
        self.repo_root = repo_root
        self.max_files = max_files
        self.max_file_size_bytes = max_file_size_bytes

    def build_inventory(self) -> Tuple[List[SourceFileEntry], FileInventorySummary]:
        entries: List[SourceFileEntry] = []
        summary = FileInventorySummary()

        for root, dirs, files in os.walk(self.repo_root):
            # Prune excluded directories
            original_dirs = list(dirs)
            dirs[:] = [
                d for d in dirs 
                if d not in EXCLUDED_DIR_NAMES and not d.startswith(".")
            ]
            for excluded in set(original_dirs) - set(dirs):
                summary.exclusions[f"directory:{excluded}"] = summary.exclusions.get(f"directory:{excluded}", 0) + 1

            for f in files:
                abs_path = os.path.join(root, f)
                rel_path = os.path.relpath(abs_path, self.repo_root).replace("\\", "/")
                ext = os.path.splitext(f)[1].lower()
                summary.total_files += 1

                # Check binary exclusion
                if ext in BINARY_EXTENSIONS:
                    summary.skipped_files += 1
                    summary.exclusions["binary_asset"] = summary.exclusions.get("binary_asset", 0) + 1
                    continue

                # Check file size
                try:
                    size_bytes = os.path.getsize(abs_path)
                except OSError:
                    size_bytes = 0

                if size_bytes > self.max_file_size_bytes:
                    summary.skipped_files += 1
                    summary.exclusions["oversized_file"] = summary.exclusions.get("oversized_file", 0) + 1
                    continue

                # Count lines and classify
                lines_count = 0
                try:
                    with open(abs_path, "r", encoding="utf-8", errors="ignore") as fp:
                        lines_count = sum(1 for _ in fp)
                except Exception:
                    pass

                lang = EXTENSION_TO_LANGUAGE.get(ext, "Unknown")
                classification = self._classify_file(rel_path, f, ext)

                is_eligible = ext in [
                    ".py", ".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte",
                    ".java", ".cs", ".php", ".json", ".yaml", ".yml", ".graphql", ".gql"
                ]

                entry = SourceFileEntry(
                    rel_path=rel_path,
                    abs_path=abs_path,
                    file_name=f,
                    extension=ext,
                    language=lang,
                    classification=classification,
                    size_bytes=size_bytes,
                    lines_count=lines_count,
                    is_eligible=is_eligible,
                    exclusion_reason=None if is_eligible else "unsupported_language_or_asset"
                )
                entries.append(entry)

                if is_eligible:
                    summary.analyzed_files += 1
                    summary.total_lines += lines_count
                    summary.languages[lang] = summary.languages.get(lang, 0) + 1
                    summary.classifications[classification] = summary.classifications.get(classification, 0) + 1
                else:
                    summary.skipped_files += 1
                    summary.exclusions["non_analyzable_extension"] = summary.exclusions.get("non_analyzable_extension", 0) + 1

                if len(entries) >= self.max_files:
                    summary.exclusions["max_files_limit_reached"] = 1
                    break

        return entries, summary

    def _classify_file(self, rel_path: str, filename: str, ext: str) -> str:
        lower_path = rel_path.lower()
        lower_name = filename.lower()

        if any(t in lower_path for t in ["test", "tests", "__tests__", "spec", "specs"]) or lower_name.endswith((".test.js", ".test.ts", ".test.py", "_test.py", ".spec.ts", ".spec.js")):
            return "TEST"
        if lower_name in ["package.json", "requirements.txt", "pyproject.toml", "composer.json", "pom.xml", "build.gradle", "cargo.toml"]:
            return "MANIFEST"
        if lower_name.endswith((".json", ".yaml", ".yml")) and any(s in lower_name for s in ["swagger", "openapi", "api-spec", "postman"]):
            return "SPECIFICATION"
        if any(c in lower_path for c in ["controller", "controllers"]):
            return "CONTROLLER"
        if any(r in lower_path for r in ["route", "routes", "router", "routers"]):
            return "ROUTE"
        if any(m in lower_path for m in ["middleware", "middlewares"]):
            return "MIDDLEWARE"
        if any(s in lower_path for s in ["model", "models", "schema", "schemas", "dto", "dtos"]):
            return "SCHEMA"
        if ext in [".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".cs", ".php", ".vue", ".svelte"]:
            return "SOURCE"
        return "OTHER"
