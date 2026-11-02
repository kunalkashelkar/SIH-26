"""
Source-Aware Context Enricher for Parameter Context and Test Selection.
Enriches parameter context with AST validation schemas, controller mappings,
authentication guards, and schema constraints to generate targeted test cases.
"""
import logging
from typing import Dict, Any, Optional, List
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Endpoint, Parameter
from app.models.discovery import DiscoveredAsset, DiscoveredRoute, EndpointParameter, SourceEvidence
from app.scanner.context.parameter_context import ParameterContext

logger = logging.getLogger(__name__)

class ContextEnricher:
    """
    Enriches ParameterContext with source code metadata and schema constraints.
    """

    @classmethod
    async def enrich_context(
        cls,
        db: AsyncSession,
        scan_id: str,
        context: ParameterContext,
        endpoint: Endpoint,
        parameter: Parameter
    ) -> ParameterContext:
        """
        Enriches ParameterContext using DiscoveredAsset and EndpointParameter data.
        """
        # Look for matching DiscoveredAsset by path and method
        method = (endpoint.method or "GET").upper()
        res = await db.execute(
            select(DiscoveredAsset)
            .options(
                selectinload(DiscoveredAsset.source_evidences),
                selectinload(DiscoveredAsset.parameters)
            )
            .where(
                DiscoveredAsset.scan_id == scan_id,
                DiscoveredAsset.path == endpoint.path,
                DiscoveredAsset.method == method
            )
        )
        asset = res.scalars().first()
        if not asset:
            return context

        # 1. Enrich with Source Evidence (Source File, Line, Framework)
        if asset.source_evidences:
            s_ev = asset.source_evidences[0]
            context.metadata["source_file"] = s_ev.file_path
            context.metadata["source_line"] = s_ev.line_start
            context.metadata["framework"] = s_ev.rule_name or (asset.metadata_json.get("framework") if asset.metadata_json else None)

        # 2. Enrich with Route Details & Authentication Guards
        r_res = await db.execute(select(DiscoveredRoute).where(DiscoveredRoute.asset_id == asset.id))
        routes = r_res.scalars().all()
        if routes:
            route = routes[0]
            context.metadata["handler_name"] = route.handler_name
            context.metadata["auth_required"] = route.auth_required
            if route.auth_required:
                context.is_sensitive = True
                if "AUTH_BYPASS" not in context.recommended_tests:
                    context.recommended_tests.append("AUTH_BYPASS")

        # 3. Enrich with Schema and Parameter Constraints
        for ep_param in asset.parameters:
            if ep_param.name == parameter.name:
                context.metadata["is_required"] = ep_param.is_required
                context.metadata["value_type"] = ep_param.value_type
                if ep_param.example_value:
                    context.metadata["example_value"] = ep_param.example_value

                # Refine tests based on AST parameter type
                val_type_lower = (ep_param.value_type or "").lower()
                if any(t in val_type_lower for t in ["int", "number", "float", "numeric"]):
                    context.type = "numeric"
                    if "SQLI" not in context.recommended_tests:
                        context.recommended_tests.append("SQLI")
                    if "TYPE_CONFUSION" not in context.recommended_tests:
                        context.recommended_tests.append("TYPE_CONFUSION")
                elif any(t in val_type_lower for t in ["email", "credential", "auth"]):
                    context.metadata["semantic_type"] = "credential"
                    if "AUTH_BYPASS" not in context.recommended_tests:
                        context.recommended_tests.append("AUTH_BYPASS")
                elif any(t in val_type_lower for t in ["uuid", "id"]):
                    context.type = "identifier"
                    if "IDOR" not in context.recommended_tests:
                        context.recommended_tests.append("IDOR")
                break

        return context
