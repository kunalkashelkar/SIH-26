"""
Source Code and Runtime Correlation Engine Coordinator.
Fuses static repository discovery with dynamic website crawling inventory,
performs endpoint matching, asset classification, discrepancy analysis,
and constructs the Unified Attack Surface Graph.
"""
import asyncio
import logging
from typing import Dict, Any, List, Optional, Set
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Scan, Target, Endpoint, Parameter, ScanLog
from app.models.discovery import (
    AssetType, DiscoveryStatus, DiscoverySource, RelationshipType,
    DiscoveredAsset, DiscoveredRoute, DiscoveredForm, SourceEvidence,
    RuntimeEvidence, EndpointParameter, AuthenticationObservation,
    AssetRelationship, DiscoveryEvent, DiscoveryError
)
from app.scanner.discovery.correlation.matcher import EndpointPathMatcher, MatchResult
from app.scanner.discovery.correlation.classifier import AssetClassifier, ConfidenceLevel
from app.scanner.discovery.correlation.diff_analyzer import DifferenceAnalyzer, DiscrepancyItem
from app.scanner.discovery.correlation.graph_builder import UnifiedAttackSurfaceGraphBuilder

logger = logging.getLogger(__name__)

class CorrelationEngine:
    """
    Combines GitHub source code discovery with live website crawling.
    """

    def __init__(self, scan_id: str, db: AsyncSession, config: Optional[Dict[str, Any]] = None):
        self.scan_id = scan_id
        self.db = db
        self.config = config or {}

    async def _log(self, level: str, message: str, phase: str = "CORRELATION"):
        self.db.add(ScanLog(scan_id=self.scan_id, level=level, message=message))
        self.db.add(DiscoveryEvent(scan_id=self.scan_id, event_type=level, phase=phase, message=message))
        await self.db.commit()

    async def run(self, cancel_event: asyncio.Event) -> Dict[str, Any]:
        """Execute the complete correlation pipeline."""
        await self._log("INFO", f"[CORRELATION] Starting source/runtime correlation for scan {self.scan_id}")

        # 1. Fetch Scan Record
        scan_stmt = select(Scan).where(Scan.id == self.scan_id)
        s_res = await self.db.execute(scan_stmt)
        scan = s_res.scalar_one_or_none()
        website_url = scan.website_url if scan else None
        repo_url = scan.repository_url if scan else None

        # 2. Fetch Assets and Supporting Evidence
        assets_res = await self.db.execute(
            select(DiscoveredAsset)
            .options(
                selectinload(DiscoveredAsset.source_evidences),
                selectinload(DiscoveredAsset.runtime_evidences),
                selectinload(DiscoveredAsset.parameters)
            )
            .where(DiscoveredAsset.scan_id == self.scan_id)
        )
        all_assets = assets_res.scalars().all()

        routes_res = await self.db.execute(select(DiscoveredRoute).where(DiscoveredRoute.scan_id == self.scan_id))
        all_routes = routes_res.scalars().all()

        forms_res = await self.db.execute(select(DiscoveredForm).where(DiscoveredForm.scan_id == self.scan_id))
        all_forms = forms_res.scalars().all()

        auth_res = await self.db.execute(select(AuthenticationObservation).where(AuthenticationObservation.scan_id == self.scan_id))
        all_auth = auth_res.scalars().all()

        # Partition Assets into Source-Defined and Runtime-Observed
        source_assets: List[DiscoveredAsset] = []
        runtime_assets: List[DiscoveredAsset] = []

        for a in all_assets:
            has_source_ev = len(a.source_evidences) > 0 or a.discovery_status == DiscoveryStatus.SOURCE_ONLY
            has_runtime_ev = len(a.runtime_evidences) > 0 or a.discovery_status == DiscoveryStatus.RUNTIME_ONLY

            if has_source_ev and not has_runtime_ev:
                source_assets.append(a)
            elif has_runtime_ev and not has_source_ev:
                runtime_assets.append(a)
            elif has_source_ev and has_runtime_ev:
                source_assets.append(a)
                runtime_assets.append(a)
            else:
                # Default by asset type
                if a.asset_type in [AssetType.FRONTEND_ROUTE, AssetType.BACKEND_API_OPERATION]:
                    source_assets.append(a)
                else:
                    runtime_assets.append(a)

        await self._log(
            "INFO",
            f"[CORRELATION] Found {len(source_assets)} source-defined assets and {len(runtime_assets)} runtime-observed assets."
        )

        # 3. Match Source Assets with Runtime Assets
        matches: List[Dict[str, Any]] = []
        matched_source_ids: Set[str] = set()
        matched_runtime_ids: Set[str] = set()

        for s_asset in source_assets:
            if cancel_event.is_set():
                break

            s_path = s_asset.path or s_asset.name or "/"
            s_method = s_asset.method or "GET"

            best_match: Optional[Tuple[DiscoveredAsset, MatchResult]] = None

            for r_asset in runtime_assets:
                r_path = r_asset.path or r_asset.url or "/"
                r_method = r_asset.method or "GET"

                match_result = EndpointPathMatcher.match(
                    source_path=s_path,
                    source_method=s_method,
                    runtime_path=r_path,
                    runtime_method=r_method
                )

                if match_result.is_match:
                    if best_match is None or match_result.confidence > best_match[1].confidence:
                        best_match = (r_asset, match_result)

            if best_match:
                r_asset, m_res = best_match
                matched_source_ids.add(s_asset.id)
                matched_runtime_ids.add(r_asset.id)

                matches.append({
                    "source_id": s_asset.id,
                    "runtime_id": r_asset.id,
                    "source_key": f"{s_method} {s_path}",
                    "runtime_key": f"{r_asset.method} {r_asset.path}",
                    "confidence": m_res.confidence,
                    "match_type": m_res.match_type,
                    "matched_parameters": m_res.matched_parameters,
                    "explanation": m_res.explanation,
                    "source": {
                        "path": s_path,
                        "method": s_method,
                        "source_file": s_asset.metadata_json.get("file_path") if s_asset.metadata_json else None,
                        "line_start": s_asset.metadata_json.get("line_start") if s_asset.metadata_json else None,
                        "framework": s_asset.metadata_json.get("framework") if s_asset.metadata_json else None,
                        "auth_required": any(r.auth_required for r in all_routes if r.asset_id == s_asset.id),
                        "parameters": [{"name": p.name, "location": p.location, "is_required": p.is_required} for p in s_asset.parameters]
                    },
                    "runtime": {
                        "path": r_asset.path,
                        "method": r_asset.method,
                        "status_code": r_asset.metadata_json.get("status_code", 200) if r_asset.metadata_json else 200,
                        "query_parameters": [p.name for p in r_asset.parameters if p.location == "query"]
                    }
                })

                # Create AssetRelationship for Match
                rel = AssetRelationship(
                    scan_id=self.scan_id,
                    source_asset_id=s_asset.id,
                    target_asset_id=r_asset.id,
                    relationship_type=RelationshipType.CORRELATED_WITH,
                    metadata_json={
                        "confidence": m_res.confidence,
                        "match_type": m_res.match_type,
                        "matched_parameters": m_res.matched_parameters,
                        "explanation": m_res.explanation
                    }
                )
                self.db.add(rel)

                # Update Asset Classification and Confidence
                s_asset.discovery_status = DiscoveryStatus.SOURCE_AND_RUNTIME_MATCH
                s_asset.confidence = m_res.confidence
                r_asset.discovery_status = DiscoveryStatus.SOURCE_AND_RUNTIME_MATCH
                r_asset.confidence = m_res.confidence

        # 4. Classify Unmatched Assets
        for s_asset in source_assets:
            if s_asset.id not in matched_source_ids:
                status, level, score, exp = AssetClassifier.classify_asset(has_source=True, has_runtime=False)
                s_asset.discovery_status = status
                s_asset.confidence = score
                if s_asset.metadata_json:
                    s_asset.metadata_json["classification_explanation"] = exp

        for r_asset in runtime_assets:
            if r_asset.id not in matched_runtime_ids:
                status_code = r_asset.metadata_json.get("status_code", 200) if r_asset.metadata_json else 200
                status, level, score, exp = AssetClassifier.classify_asset(
                    has_source=False,
                    has_runtime=True,
                    response_status=status_code
                )
                r_asset.discovery_status = status
                r_asset.confidence = score
                if r_asset.metadata_json:
                    r_asset.metadata_json["classification_explanation"] = exp

        await self.db.commit()

        # 5. Difference and Discrepancy Analysis
        src_route_data = [
            {
                "path": r.route_pattern,
                "method": r.method,
                "source_file": r.source_file,
                "line_start": r.source_line,
                "framework": r.framework,
                "auth_required": r.auth_required
            }
            for r in all_routes
        ]
        rt_endpoint_data = [
            {
                "path": a.path or "/",
                "method": a.method or "GET",
                "url": a.url,
                "status_code": a.metadata_json.get("status_code", 200) if a.metadata_json else 200,
                "source": a.metadata_json.get("resource_type", "HTML") if a.metadata_json else "HTML"
            }
            for a in runtime_assets
        ]

        discrepancies = DifferenceAnalyzer.analyze_discrepancies(
            source_routes=src_route_data,
            runtime_endpoints=rt_endpoint_data,
            matches=matches
        )

        for disc in discrepancies:
            if disc.severity in ["MEDIUM", "HIGH"]:
                await self._log(
                    "WARN",
                    f"[{disc.discrepancy_type}] {disc.description}"
                )

        # 6. Build Unified Attack Surface Graph
        asset_dicts = [
            {
                "id": a.id,
                "asset_type": a.asset_type,
                "path": a.path,
                "method": a.method,
                "discovery_status": a.discovery_status,
                "confidence": a.confidence,
                "metadata_json": a.metadata_json
            }
            for a in all_assets
        ]
        route_dicts = [
            {
                "id": r.id,
                "asset_id": r.asset_id,
                "route_pattern": r.route_pattern,
                "method": r.method,
                "framework": r.framework,
                "source_file": r.source_file,
                "source_line": r.source_line,
                "handler_name": r.handler_name,
                "auth_required": r.auth_required
            }
            for r in all_routes
        ]
        form_dicts = [
            {
                "id": f.id,
                "action": f.action,
                "method": f.method,
                "page_url": f.page_url
            }
            for f in all_forms
        ]
        rel_dicts = [
            {
                "source_asset_id": m["source_id"],
                "target_asset_id": m["runtime_id"],
                "relationship_type": RelationshipType.CORRELATED_WITH,
                "confidence": m["confidence"],
                "metadata_json": {"explanation": m["explanation"]}
            }
            for m in matches
        ]

        graph_builder = UnifiedAttackSurfaceGraphBuilder(
            scan_id=self.scan_id,
            website_url=website_url,
            repo_url=repo_url
        )
        graph = graph_builder.build_graph(
            assets=asset_dicts,
            routes=route_dicts,
            forms=form_dicts,
            client_calls=[],
            auth_observations=[],
            relationships=rel_dicts
        )
        graph_json = graph_builder.to_json()

        # Store graph in scan configuration
        if scan:
            cfg = dict(scan.configuration or {})
            cfg["attack_surface_graph"] = {
                "total_nodes": graph_json["total_nodes"],
                "total_edges": graph_json["total_edges"]
            }
            scan.configuration = cfg
            await self.db.commit()

        summary = {
            "total_matches": len(matches),
            "source_only_count": len(source_assets) - len(matched_source_ids),
            "runtime_only_count": len(runtime_assets) - len(matched_runtime_ids),
            "discrepancies_count": len(discrepancies),
            "graph_nodes": graph_json["total_nodes"],
            "graph_edges": graph_json["total_edges"]
        }

        await self._log(
            "SUCCESS",
            f"[CORRELATION] Correlation finished. Correlated matches: {summary['total_matches']}; "
            f"Source-only: {summary['source_only_count']}; Runtime-only: {summary['runtime_only_count']}; "
            f"Discrepancies identified: {summary['discrepancies_count']}; Graph nodes: {summary['graph_nodes']}"
        )

        return summary
