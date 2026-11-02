"""
Schema and Parameter Analyzer for Pydantic Models, TypeScript Interfaces, and Zod Schemas.
"""
import ast
import logging
import os
import re
from typing import List, Dict, Any, Optional

from app.scanner.discovery.source.models import SourceParameter

logger = logging.getLogger(__name__)

# TypeScript interface: interface LoginDTO { email: string; password?: string; }
TS_INTERFACE_REGEX = re.compile(
    r'(?:interface|type)\s+([A-Za-z0-9_]+)(?:\s*=\s*\{|\s*\{)([^}]+)\}',
    re.MULTILINE
)

# Zod object schema: const LoginSchema = z.object({ email: z.string().email(), age: z.number().optional() })
ZOD_OBJECT_REGEX = re.compile(
    r'(?:const|let|var)\s+([A-Za-z0-9_]+)\s*=\s*z\.object\s*\(\s*\{([^}]+)\}\s*\)',
    re.MULTILINE
)

class SchemaAnalyzer:
    """
    Parses request and response data schemas from Python AST and TypeScript source files.
    """

    def __init__(self, repo_root: str):
        self.repo_root = repo_root

    def parse_python_pydantic(self, file_path: str) -> Dict[str, List[SourceParameter]]:
        """Extract Pydantic BaseModel classes and their fields via Python AST."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
            tree = ast.parse(source, filename=file_path)
        except Exception:
            return {}

        schemas: Dict[str, List[SourceParameter]] = {}

        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                # Check if inherits from BaseModel or Schema
                is_pydantic = any(
                    self._get_base_name(b) in ["BaseModel", "Schema", "BaseSchema"]
                    for b in node.bases
                )
                if is_pydantic:
                    fields: List[SourceParameter] = []
                    for item in node.body:
                        # Type annotation: field_name: str = "default"
                        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                            fname = item.target.id
                            ftype = self._ast_to_type_str(item.annotation)
                            has_default = item.value is not None
                            is_optional = "Optional" in ftype or has_default
                            fields.append(SourceParameter(
                                name=fname,
                                location="body",
                                value_type=ftype,
                                is_required=not is_optional
                            ))
                    if fields:
                        schemas[node.name] = fields

        return schemas

    def parse_typescript_interfaces(self, file_path: str) -> Dict[str, List[SourceParameter]]:
        """Extract TypeScript interfaces and type definitions."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return {}

        schemas: Dict[str, List[SourceParameter]] = {}

        # 1. Parse TypeScript interfaces
        for match in TS_INTERFACE_REGEX.finditer(content):
            schema_name = match.group(1)
            body = match.group(2)
            fields: List[SourceParameter] = []

            for line in body.splitlines():
                line = line.strip().rstrip(";,")
                if not line or line.startswith("//"):
                    continue

                if ":" in line:
                    parts = line.split(":", 1)
                    prop_name = parts[0].strip()
                    prop_type = parts[1].strip()

                    is_optional = prop_name.endswith("?")
                    clean_name = prop_name.rstrip("?")

                    fields.append(SourceParameter(
                        name=clean_name,
                        location="body",
                        value_type=prop_type,
                        is_required=not is_optional
                    ))

            if fields:
                schemas[schema_name] = fields

        # 2. Parse Zod schemas
        for match in ZOD_OBJECT_REGEX.finditer(content):
            schema_name = match.group(1)
            body = match.group(2)
            fields: List[SourceParameter] = []

            for line in body.splitlines():
                line = line.strip().rstrip(",")
                if not line or line.startswith("//"):
                    continue

                if ":" in line:
                    parts = line.split(":", 1)
                    prop_name = parts[0].strip()
                    zod_rule = parts[1].strip()

                    is_optional = "optional()" in zod_rule or "nullable()" in zod_rule
                    prop_type = "string"
                    if "z.number" in zod_rule:
                        prop_type = "number"
                    elif "z.boolean" in zod_rule:
                        prop_type = "boolean"
                    elif "z.array" in zod_rule:
                        prop_type = "array"

                    fields.append(SourceParameter(
                        name=prop_name,
                        location="body",
                        value_type=prop_type,
                        is_required=not is_optional
                    ))

            if fields:
                schemas[schema_name] = fields

        return schemas

    def _get_base_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return ""

    def _ast_to_type_str(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        elif isinstance(node, ast.Subscript):
            val = self._ast_to_type_str(node.value)
            sl = self._ast_to_type_str(node.slice)
            return f"{val}[{sl}]"
        elif isinstance(node, ast.Constant):
            return str(node.value)
        return "any"
