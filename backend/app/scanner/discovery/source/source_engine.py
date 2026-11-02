"""
Source Code Discovery Engine Coordinator.
Coordinates repository acquisition, framework detection, AST parsing,
API client extraction, schema analysis, static security vulnerability analysis,
and database inventory persistence.
"""
import asyncio
import logging
import os
import shutil
from typing import Dict, Any, Optional, List
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Endpoint, Parameter, ScanLog, Finding, Evidence
from app.models.discovery import (
    AssetType, DiscoveryStatus, DiscoverySource,
    DiscoveredAsset, DiscoveredRoute, SourceFile, SourceEvidence,
    EndpointParameter, AuthenticationObservation, RepositoryProfile,
    DiscoveryEvent, DiscoveryError
)
from app.scanner.discovery.source.models import DiscoveredSourceRoute, DiscoveredClientCall
from app.services.repository.repository_downloader import RepositoryDownloader
from app.services.repository.file_inventory import FileInventoryBuilder
from app.scanner.discovery.source.framework_detector import SourceFrameworkDetector
from app.scanner.discovery.source.parsers.python_fastapi import PythonRouteParser
from app.scanner.discovery.source.parsers.python_django import DjangoRouteParser
from app.scanner.discovery.source.parsers.js_routes import JavaScriptRouteParser
from app.scanner.discovery.source.parsers.http_client import HttpClientAnalyzer
from app.scanner.discovery.source.parsers.schemas import SchemaAnalyzer
from app.scanner.discovery.source.parsers.auth_detector import AuthDetector
from app.scanner.discovery.source.parsers.api_specs import StaticApiSpecParser
from app.scanner.discovery.source.static_security import StaticSecurityAnalyzer

logger = logging.getLogger(__name__)

class SourceCodeDiscoveryEngine:
    """
    Unified static source code analyzer for GITHUB_ONLY and HYBRID modes.
    Safely inspects repository contents without executing code.
    """

    def __init__(
        self,
        scan_id: str,
        repo_url: str,
        db: AsyncSession,
        config: Optional[Dict[str, Any]] = None
    ):
        self.scan_id = scan_id
        self.repo_url = repo_url.strip()
        self.db = db
        self.config = config or {}

        self.branch = self.config.get("repository_branch", "main")
        self.commit_sha = self.config.get("repository_commit_sha")
        self.auth_token = self.config.get("github_token")

    async def _log(self, level: str, message: str, phase: str = "SOURCE_DISCOVERY"):
        self.db.add(ScanLog(scan_id=self.scan_id, level=level, message=message))
        self.db.add(DiscoveryEvent(scan_id=self.scan_id, event_type=level, phase=phase, message=message))
        await self.db.commit()

    async def _set_stage(self, stage: str, progress: Optional[int] = None):
        """Update scan current_stage and progress in DB."""
        from app.models.models import Scan
        res = await self.db.execute(select(Scan).where(Scan.id == self.scan_id))
        scan = res.scalar_one_or_none()
        if scan:
            scan.current_stage = stage
            if progress is not None:
                scan.progress = progress
            await self.db.commit()

    async def run(self, cancel_event: asyncio.Event) -> Dict[str, Any]:
        """Execute full source discovery pipeline."""
        await self._log("INFO", f"[SOURCE_ENGINE] Initializing source code discovery for {self.repo_url} (branch: {self.branch})")

        downloader = RepositoryDownloader(
            auth_token=self.auth_token,
            max_size_mb=150,
            max_files=10000
        )

        summary = {
            "files_analyzed": 0,
            "routes_discovered": 0,
            "client_calls_discovered": 0,
            "auth_observations": 0,
            "static_findings_discovered": 0,
            "detected_frameworks": [],
            "detected_languages": [],
            "commit_sha": None
        }

        repo_dir = None
        try:
            await self._set_stage("VALIDATING_REPOSITORY", 10)
            await self._set_stage("DOWNLOADING_REPOSITORY", 15)
            repo_dir, repo_meta = await downloader.acquire_repository(
                repo_url=self.repo_url,
                branch=self.branch,
                commit_sha=self.commit_sha
            )
            summary["commit_sha"] = repo_meta.resolved_commit_sha
            if cancel_event.is_set():
                return summary

            await self._log(
                "SUCCESS",
                f"[ACQUISITION] Repository acquired successfully. "
                f"Resolved branch: {repo_meta.selected_branch}, Commit SHA: {repo_meta.resolved_commit_sha[:10] if repo_meta.resolved_commit_sha else 'HEAD'}"
            )

            # ------------------------------------------------------------------
            # 1. Source File Inventory
            # ------------------------------------------------------------------
            await self._set_stage("BUILDING_INVENTORY", 25)
            await self._log("INFO", "[FILE_INVENTORY] Building source file inventory and filtering non-source assets...")
            inv_builder = FileInventoryBuilder(repo_root=repo_dir)
            file_entries, inv_summary = inv_builder.build_inventory()

            for entry in file_entries:
                sf = SourceFile(
                    scan_id=self.scan_id,
                    file_path=entry.rel_path,
                    language=entry.language.upper(),
                    file_type=entry.classification,
                    lines_count=entry.lines_count
                )
                self.db.add(sf)
            await self.db.commit()

            await self._log(
                "SUCCESS",
                f"[FILE_INVENTORY] Discovered {inv_summary.total_files} files: "
                f"{inv_summary.analyzed_files} eligible for AST analysis, {inv_summary.skipped_files} excluded/skipped."
            )

            # ------------------------------------------------------------------
            # 2. Framework and Language Detection
            # ------------------------------------------------------------------
            await self._set_stage("DETECTING_FRAMEWORKS", 35)
            await self._log("INFO", "[FRAMEWORK_DETECTOR] Analyzing manifests and repository structure...")
            det_res = SourceFrameworkDetector.detect(repo_dir)
            detected_languages = det_res["languages"]
            detected_frameworks = det_res["frameworks"]
            summary["detected_languages"] = detected_languages
            summary["detected_frameworks"] = detected_frameworks

            # Update RepositoryProfile
            p_res = await self.db.execute(select(RepositoryProfile).where(RepositoryProfile.scan_id == self.scan_id))
            profile = p_res.scalar_one_or_none()
            if profile:
                profile.detected_languages = detected_languages
                profile.detected_frameworks = detected_frameworks
                profile.commit_sha = repo_meta.resolved_commit_sha
                profile.branch = repo_meta.selected_branch
                profile.total_files_analyzed = inv_summary.analyzed_files
                await self.db.commit()

            await self._log("SUCCESS", f"[FRAMEWORK_DETECTOR] Detected Frameworks: {detected_frameworks}; Languages: {detected_languages}")

            # Initialize Parsers
            py_parser = PythonRouteParser(repo_dir)
            django_parser = DjangoRouteParser(repo_dir)
            js_parser = JavaScriptRouteParser(repo_dir)
            client_analyzer = HttpClientAnalyzer(repo_dir)
            schema_analyzer = SchemaAnalyzer(repo_dir)
            auth_detector = AuthDetector(repo_dir)
            spec_parser = StaticApiSpecParser(repo_dir)

            all_routes: List[DiscoveredSourceRoute] = []
            all_client_calls: List[DiscoveredClientCall] = []

            # ------------------------------------------------------------------
            # 3. Parse Source Files for Routes, Clients, Auth
            # ------------------------------------------------------------------
            for entry in file_entries:
                if cancel_event.is_set():
                    break
                if not entry.is_eligible:
                    continue

                abs_file = entry.abs_path
                rel_file = entry.rel_path
                ext = entry.extension

                # A. Parse Python
                if ext == ".py":
                    routes = py_parser.parse_file(abs_file)
                    all_routes.extend(routes)

                    if "django" in [fw.lower() for fw in detected_frameworks] or "urls.py" in rel_file:
                        dj_routes = django_parser.parse_file(abs_file)
                        all_routes.extend(dj_routes)

                # B. Parse JS/TS files
                elif ext in [".js", ".jsx", ".ts", ".tsx", ".vue"]:
                    routes = js_parser.parse_file(abs_file)
                    all_routes.extend(routes)

                    calls = client_analyzer.parse_file(abs_file)
                    all_client_calls.extend(calls)

                # C. Check Authentication patterns
                auth_obs = auth_detector.analyze_file(abs_file)
                for obs in auth_obs:
                    db_obs = AuthenticationObservation(
                        scan_id=self.scan_id,
                        auth_type=obs.get("auth_type", "UNKNOWN"),
                        roles_detected=obs.get("roles_allowed", []),
                        is_authenticated=obs.get("is_enforced", False),
                        metadata_json={
                            "source_file": obs.get("file_path"),
                            "source_line": obs.get("line_number"),
                            "mechanism": obs.get("mechanism"),
                            "roles_allowed": obs.get("roles_allowed", []),
                            "is_enforced": obs.get("is_enforced", False)
                        }
                    )
                    self.db.add(db_obs)
                    summary["auth_observations"] += 1

            # ------------------------------------------------------------------
            # 4. Static API Specification Discovery (OpenAPI, Postman, GraphQL)
            # ------------------------------------------------------------------
            if not cancel_event.is_set():
                spec_routes = spec_parser.parse_repository()
                if spec_routes:
                    await self._log("INFO", f"[SPEC_PARSER] Discovered {len(spec_routes)} routes from repository API specifications.")
                    all_routes.extend(spec_routes)

            await self.db.commit()

            # ------------------------------------------------------------------
            # 5. Deduplicate and Persist Discovered Assets and Routes
            # ------------------------------------------------------------------
            persisted_assets: Dict[str, DiscoveredAsset] = {}

            for route in all_routes:
                asset_key = f"{route.method} {route.path}"
                asset = persisted_assets.get(asset_key)

                if not asset:
                    a_res = await self.db.execute(
                        select(DiscoveredAsset).where(
                            DiscoveredAsset.scan_id == self.scan_id,
                            DiscoveredAsset.identifier == asset_key
                        )
                    )
                    asset = a_res.scalar_one_or_none()

                if not asset:
                    asset_type = AssetType.FRONTEND_ROUTE if route.route_type == "FRONTEND" else AssetType.BACKEND_API_OPERATION
                    asset = DiscoveredAsset(
                        scan_id=self.scan_id,
                        asset_type=asset_type,
                        identifier=asset_key,
                        name=route.path,
                        path=route.path,
                        url=route.path,
                        method=route.method,
                        discovery_status=DiscoveryStatus.SOURCE_DEFINED,
                        confidence=route.confidence,
                        metadata_json={
                            "framework": route.framework,
                            "handler_name": route.handler_name,
                            "file_path": route.file_path,
                            "line_start": route.line_start
                        }
                    )
                    self.db.add(asset)
                    await self.db.commit()
                    await self.db.refresh(asset)
                    persisted_assets[asset_key] = asset

                # DiscoveredRoute record
                d_route = DiscoveredRoute(
                    scan_id=self.scan_id,
                    asset_id=asset.id,
                    route_pattern=route.path,
                    method=route.method,
                    route_type=route.route_type,
                    framework=route.framework,
                    source_file=route.file_path,
                    source_line=route.line_start,
                    handler_name=route.handler_name,
                    auth_required=route.auth_required
                )
                self.db.add(d_route)

                # SourceEvidence record
                evidence = SourceEvidence(
                    scan_id=self.scan_id,
                    asset_id=asset.id,
                    file_path=route.file_path,
                    line_start=route.line_start,
                    line_end=route.line_end,
                    snippet=route.code_snippet,
                    confidence=route.confidence,
                    ast_node_type="ROUTE_DECLARATION",
                    rule_name=route.framework,
                    verification_status=DiscoveryStatus.SOURCE_DEFINED,
                    metadata_json={"method": route.method, "path": route.path}
                )
                self.db.add(evidence)

                # Parameters
                for p in route.parameters:
                    param = EndpointParameter(
                        scan_id=self.scan_id,
                        asset_id=asset.id,
                        name=p.name,
                        location=p.location,
                        value_type=p.value_type,
                        is_required=p.is_required
                    )
                    self.db.add(param)

            # Persist Client Calls
            for call in all_client_calls:
                call_key = f"{call.method} {call.url_pattern}"
                if call_key in persisted_assets:
                    asset = persisted_assets[call_key]
                    call_ev = SourceEvidence(
                        scan_id=self.scan_id,
                        asset_id=asset.id,
                        file_path=call.file_path,
                        line_start=call.line_number,
                        line_end=call.line_number + 1,
                        snippet=call.code_snippet,
                        confidence=0.88,
                        ast_node_type="CLIENT_CALL",
                        rule_name=call.client_library,
                        verification_status=DiscoveryStatus.SOURCE_DEFINED,
                        metadata_json={"is_dynamic": call.is_dynamic, "variables": call.dynamic_variables}
                    )
                    self.db.add(call_ev)

            await self.db.commit()

            # ------------------------------------------------------------------
            # 6. Static Application Security Analysis (SAST)
            # ------------------------------------------------------------------
            if not cancel_event.is_set():
                await self._log("INFO", "[STATIC_SECURITY] Executing static security analysis on extracted source code...")
                sast_analyzer = StaticSecurityAnalyzer(repo_dir)
                raw_findings = sast_analyzer.analyze_repository()
                
                for sf in raw_findings:
                    # Match with an endpoint if path matches
                    matched_endpoint_id = None
                    for asset in persisted_assets.values():
                        if asset.metadata_json and asset.metadata_json.get("file_path") == sf.file_path:
                            matched_endpoint_id = asset.id
                            break

                    db_finding = Finding(
                        scan_id=self.scan_id,
                        endpoint_id=matched_endpoint_id,
                        title=sf.title,
                        vulnerability_type=sf.title,
                        severity=sf.severity,
                        confidence=f"{sf.confidence}",
                        priority="P1" if sf.severity in ["CRITICAL", "HIGH"] else "P3",
                        status="open",
                        description=sf.rationale,
                        technical_details=f"File: {sf.file_path} (lines {sf.line_start}-{sf.line_end})\nSnippet:\n{sf.snippet}",
                        impact=f"Potential {sf.title} vulnerability in {sf.file_path}:{sf.line_start}",
                        cwe=sf.cwe,
                        owasp_category=sf.owasp_category,
                        remediation=sf.remediation,
                        source_file=sf.file_path,
                        source_line_start=sf.line_start,
                        source_line_end=sf.line_end,
                        affected_url=sf.file_path,
                        affected_endpoint=f"{sf.file_path}:{sf.line_start}",
                        http_method="N/A",
                        detection_method="STATIC_AST",
                        validation_method="AST_MATCH"
                    )
                    self.db.add(db_finding)
                    await self.db.flush()

                    finding_evidence = Evidence(
                        finding_id=db_finding.id,
                        evidence_type="SOURCE_AST",
                        baseline_summary=f"Rule: {sf.rule_id} ({sf.cwe})",
                        test_summary=f"Detected pattern in {sf.file_path} L{sf.line_start}-L{sf.line_end}",
                        analysis=sf.snippet,
                        confidence=sf.confidence
                    )
                    self.db.add(finding_evidence)
                    summary["static_findings_discovered"] += 1

                await self.db.commit()
                await self._log(
                    "SUCCESS" if summary["static_findings_discovered"] == 0 else "WARN",
                    f"[STATIC_SECURITY] Discovered {summary['static_findings_discovered']} static security candidates."
                )

            # Update RepositoryProfile summary stats
            if profile:
                profile.total_files_analyzed = inv_summary.analyzed_files
                profile.total_routes_detected = len(persisted_assets)
                profile.total_routes_discovered = len(persisted_assets)
                await self.db.commit()

            summary["files_analyzed"] = inv_summary.analyzed_files
            summary["routes_discovered"] = len(persisted_assets)
            summary["client_calls_discovered"] = len(all_client_calls)

            await self._log(
                "SUCCESS",
                f"[SOURCE_ENGINE] Discovered {summary['routes_discovered']} source-defined routes, "
                f"{summary['client_calls_discovered']} client API calls, {summary['auth_observations']} auth observations, "
                f"{summary['static_findings_discovered']} security candidates across {inv_summary.analyzed_files} files."
            )

        except Exception as e:
            logger.error(f"[SOURCE_ENGINE] Analysis failed for {self.repo_url}: {e}", exc_info=True)
            self.db.add(DiscoveryError(
                scan_id=self.scan_id,
                component="SOURCE_CODE_DISCOVERY",
                error_type=type(e).__name__,
                message=str(e),
                source_file=self.repo_url,
                retryable=False
            ))
            await self.db.commit()
            raise
        finally:
            if repo_dir and os.path.exists(repo_dir) and not os.path.isdir(self.repo_url):
                try:
                    shutil.rmtree(repo_dir, ignore_errors=True)
                except Exception:
                    pass

        return summary
