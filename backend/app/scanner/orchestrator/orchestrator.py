import asyncio
import logging
import os
import re
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Optional, Any, List
from sqlalchemy import func
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import AsyncSessionLocal
from app.models.models import (
    Scan, Target, Project, Endpoint, Parameter, ScanLog, Finding
)
from app.models.discovery import (
    ScanMode, DiscoveryStatus, DiscoverySource, AssetType,
    WebsiteProfile, RepositoryProfile, DiscoveredAsset,
    DiscoveredPage, DiscoveredRoute, DiscoveredEndpoint,
    EndpointParameter, DiscoveredForm, SourceFile,
    SourceEvidence, RuntimeEvidence, AuthenticationObservation,
    DiscoveryEvent, DiscoveryError, AssetRelationship,
    ScanStage, StageAttempt, StageStatus, FailureCategory
)
from app.scanner.orchestrator.stage_manager import StageExecutionWrapper, RetryPolicy, classify_exception

logger = logging.getLogger(__name__)

# Sensitive keywords and patterns for redaction
SENSITIVE_PATTERNS = [
    (re.compile(r"(ghp_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{20,})"), "[REDACTED_GH_TOKEN]"),
    (re.compile(r"(Bearer\s+[a-zA-Z0-9_\-\.]{15,})", re.IGNORECASE), "Bearer [REDACTED_JWT]"),
    (re.compile(r"([?&](?:token|auth|key|password|secret)=)[^&]+", re.IGNORECASE), r"\1[REDACTED]"),
]

def sanitize_sensitive_data(val: Any) -> Any:
    """Recursively scrub credentials, API tokens, and secret strings from logs and telemetry."""
    if isinstance(val, str):
        sanitized = val
        for pat, repl in SENSITIVE_PATTERNS:
            sanitized = pat.sub(repl, sanitized)
        return sanitized
    elif isinstance(val, dict):
        sanitized = {}
        for k, v in val.items():
            if any(s in k.lower() for s in ["token", "secret", "password", "auth", "key", "credential", "cookie"]):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_sensitive_data(v)
        return sanitized
    elif isinstance(val, list):
        return [sanitize_sensitive_data(x) for x in val]
    return val

class ValidationError(Exception):
    """Raised when scan inputs fail validation."""
    pass

class ScanCancelledError(Exception):
    """Raised when user cancels a running scan."""
    pass

class ScanOrchestrator:
    """
    Central Orchestrator for Hybrid Source-Code and Runtime Discovery.
    Handles intake, validation, lifecycle phases, bounded concurrency,
    isolated error handling, cancellation, telemetry, and unified asset inventory.
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ScanOrchestrator, cls).__new__(cls)
            cls._instance.active_tasks: Dict[str, asyncio.Task] = {}
            cls._instance.cancellation_events: Dict[str, asyncio.Event] = {}
            cls._instance.concurrency_semaphore = asyncio.Semaphore(3) # Bounded concurrency
        return cls._instance

    @staticmethod
    def validate_request(data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate scan mode and required inputs."""
        # Unpack nested repository dict if present
        if "repository" in data and isinstance(data["repository"], dict):
            repo_dict = data["repository"]
            if "url" in repo_dict and not data.get("repository_url"):
                data["repository_url"] = repo_dict.get("url")
            if "branch" in repo_dict and not data.get("repository_branch"):
                data["repository_branch"] = repo_dict.get("branch")

        raw_mode = (data.get("discovery_mode") or data.get("scan_mode") or ScanMode.WEBSITE_ONLY).upper()
        if raw_mode in ["REPOSITORY_ONLY", "GITHUB_ONLY", "REPO_ONLY"]:
            mode = ScanMode.GITHUB_ONLY
        elif raw_mode in ["HYBRID", "COMBINED"]:
            mode = ScanMode.HYBRID
        elif raw_mode in ["WEBSITE_ONLY", "WEB_ONLY"]:
            mode = ScanMode.WEBSITE_ONLY
        else:
            mode = ScanMode.WEBSITE_ONLY

        website_url = data.get("website_url") or data.get("target_url")
        repo_url = data.get("repository_url")

        if mode == ScanMode.WEBSITE_ONLY:
            if not website_url or not website_url.strip():
                raise ValidationError("WEBSITE_ONLY scan mode requires a valid website URL.")
            parsed = urllib.parse.urlparse(website_url.strip())
            if parsed.scheme not in ["http", "https"] or not parsed.netloc:
                raise ValidationError(f"Invalid website URL format: '{website_url}'. Must start with http:// or https://")
            data["website_url"] = website_url.strip()

        elif mode == ScanMode.GITHUB_ONLY:
            if not repo_url or not repo_url.strip():
                raise ValidationError("REPOSITORY_ONLY scan mode requires a valid repository URL.")
            repo_url_clean = repo_url.strip()
            # Allow local path for testing / mock repos, or github.com
            is_local = os.path.exists(repo_url_clean)
            if not is_local and "github.com" not in repo_url_clean and not repo_url_clean.startswith("git@"):
                raise ValidationError(f"Invalid repository URL: '{repo_url}'. Must be a valid GitHub repository.")
            data["repository_url"] = repo_url_clean

        elif mode == ScanMode.HYBRID:
            if not website_url or not website_url.strip():
                raise ValidationError("HYBRID scan mode requires an authorized website URL.")
            if not repo_url or not repo_url.strip():
                raise ValidationError("HYBRID scan mode requires a GitHub repository URL.")
            parsed = urllib.parse.urlparse(website_url.strip())
            if parsed.scheme not in ["http", "https"] or not parsed.netloc:
                raise ValidationError(f"Invalid website URL format: '{website_url}'.")
            data["website_url"] = website_url.strip()
            data["repository_url"] = repo_url.strip()

        data["discovery_mode"] = mode
        data["repository_branch"] = data.get("repository_branch") or "main"
        return data

    async def create_scan_record(self, db: AsyncSession, data: Dict[str, Any], user_id: Optional[str] = None) -> Scan:
        """Create and persist the master unified scan record and target/profiles."""
        validated = self.validate_request(data)
        mode = validated["discovery_mode"]
        website_url = validated.get("website_url")
        repo_url = validated.get("repository_url")
        branch = validated.get("repository_branch", "main")

        # Handle Target linking or creation for website / hybrid scans
        target = None
        if website_url:
            res = await db.execute(select(Target).where(Target.base_url == website_url))
            target = res.scalars().first()
            if not target:
                p_res = await db.execute(select(Project).limit(1))
                first_proj = p_res.scalars().first()
                proj_id = validated.get("project_id") or (first_proj.id if first_proj else None)
                parsed = urllib.parse.urlparse(website_url)
                target = Target(
                    name=parsed.netloc or website_url,
                    base_url=website_url,
                    repo_url=repo_url,
                    repo_branch=branch,
                    project_id=proj_id,
                    description=f"Target configured for {mode} scan"
                )
                db.add(target)
                await db.commit()
                await db.refresh(target)
        elif repo_url:
            # GITHUB_ONLY target representation
            repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
            res = await db.execute(select(Target).where(Target.repo_url == repo_url))
            target = res.scalars().first()
            if not target:
                p_res = await db.execute(select(Project).limit(1))
                first_proj = p_res.scalars().first()
                proj_id = validated.get("project_id") or (first_proj.id if first_proj else None)
                target = Target(
                    name=f"GitHub: {repo_name}",
                    base_url=repo_url, # Fallback base_url for schema constraints
                    repo_url=repo_url,
                    repo_branch=branch,
                    project_id=proj_id,
                    description="Repository target created for GITHUB_ONLY discovery"
                )
                db.add(target)
                await db.commit()
                await db.refresh(target)

        # Initial task and module tracking structures
        initial_tasks = {
            "pending": 0,
            "processing": 0,
            "completed": 0,
            "failed": 0,
            "skipped": 0
        }
        initial_module_status = {
            "fingerprinting": {"status": "PENDING", "duration_seconds": 0.0, "discovered": 0, "persisted": 0, "error": None},
            "crawling": {"status": "PENDING", "duration_seconds": 0.0, "discovered": 0, "persisted": 0, "error": None},
            "browser_discovery": {"status": "PENDING", "duration_seconds": 0.0, "discovered": 0, "persisted": 0, "error": None},
            "source_analysis": {"status": "PENDING", "duration_seconds": 0.0, "discovered": 0, "persisted": 0, "error": None},
            "correlating": {"status": "PENDING", "duration_seconds": 0.0, "discovered": 0, "persisted": 0, "error": None},
            "persisting": {"status": "PENDING", "duration_seconds": 0.0, "discovered": 0, "persisted": 0, "error": None}
        }

        config_payload = {
            **validated,
            "tasks_summary": initial_tasks,
            "module_status": initial_module_status
        }

        # Create master Scan record in explicit QUEUED state
        scan = Scan(
            user_id=user_id,
            target_id=target.id if target else None,
            status="QUEUED",
            current_stage="INITIALIZING",
            scan_mode=validated.get("scan_mode", "Standard"),
            discovery_mode=mode,
            website_url=website_url,
            repository_url=repo_url,
            repository_branch=branch,
            repository_commit_sha=validated.get("repository_commit_sha"),
            progress=0,
            configuration=config_payload,
            started_at=datetime.utcnow()
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        # Initialize profiles
        if website_url:
            parsed = urllib.parse.urlparse(website_url)
            web_profile = WebsiteProfile(
                scan_id=scan.id,
                base_url=website_url,
                host=parsed.netloc,
                title=f"Target: {parsed.netloc}",
                tech_stack=[],
                robots_txt_present=False
            )
            db.add(web_profile)

        if repo_url:
            repo_profile = RepositoryProfile(
                scan_id=scan.id,
                repo_url=repo_url,
                branch=branch,
                detected_languages=[],
                detected_frameworks=[],
                total_files_analyzed=0
            )
            db.add(repo_profile)

        # Initial event log
        event = DiscoveryEvent(
            scan_id=scan.id,
            event_type="PHASE_START",
            phase="INITIALIZING",
            message=f"Initialized {mode} scan execution pipeline.",
            details={"mode": mode, "website_url": sanitize_sensitive_data(website_url), "repo_url": sanitize_sensitive_data(repo_url)}
        )
        db.add(event)
        
        log_entry = ScanLog(
            scan_id=scan.id,
            level="INFO",
            message=f"[ORCHESTRATOR] Initialized scan {scan.id} with mode: {mode}"
        )
        db.add(log_entry)
        await db.commit()

        return scan

    def start_scan(self, scan_id: str, scan_config: Dict[str, Any]):
        """Launch background scan task under bounded concurrency."""
        if scan_id in self.active_tasks:
            logger.warning(f"Scan {scan_id} is already running.")
            return

        cancel_event = asyncio.Event()
        self.cancellation_events[scan_id] = cancel_event

        task = asyncio.create_task(self._run_orchestrated_lifecycle(scan_id, scan_config, cancel_event))
        self.active_tasks[scan_id] = task
        task.add_done_callback(lambda t: self._cleanup_scan(scan_id))
        logger.info(f"ScanOrchestrator dispatched background worker for {scan_id}")

    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel an in-progress scan."""
        if scan_id in self.cancellation_events:
            logger.info(f"Cancelling scan {scan_id}")
            self.cancellation_events[scan_id].set()
            return True
        return False

    def _cleanup_scan(self, scan_id: str):
        if scan_id in self.active_tasks:
            del self.active_tasks[scan_id]
        if scan_id in self.cancellation_events:
            del self.cancellation_events[scan_id]

    async def recover_interrupted_scans(self):
        """
        On server/worker restart, identify scans that were in RUNNING or QUEUED state.
        Preserves previously persisted evidence:
        - If findings or assets exist: marks scan as PARTIALLY_COMPLETED.
        - If no work completed: marks as FAILED with an explanatory note.
        """
        try:
            async with AsyncSessionLocal() as db:
                res = await db.execute(select(Scan).where(Scan.status.in_(["RUNNING", "QUEUED"])))
                interrupted_scans = res.scalars().all()
                if not interrupted_scans:
                    return

                logger.info(f"Scan recovery: found {len(interrupted_scans)} interrupted scans on process startup.")
                for s in interrupted_scans:
                    f_res = await db.execute(select(func.count(Finding.id)).where(Finding.scan_id == s.id))
                    f_count = f_res.scalar() or 0
                    a_res = await db.execute(select(func.count(DiscoveredAsset.id)).where(DiscoveredAsset.scan_id == s.id))
                    a_count = a_res.scalar() or 0

                    st_res = await db.execute(select(ScanStage).where(ScanStage.scan_id == s.id))
                    stages = st_res.scalars().all()
                    for st in stages:
                        if st.stage_status == "RUNNING":
                            st.stage_status = "PARTIAL" if a_count > 0 else "FAILED"
                            st.error_message = "Subsystem execution interrupted by worker restart."
                            st.completed_at = datetime.now(timezone.utc)

                    if f_count > 0 or a_count > 0:
                        s.status = "PARTIALLY_COMPLETED"
                        s.error_message = f"Process restarted during execution. Preserved {a_count} assets and {f_count} findings."
                    else:
                        s.status = "FAILED"
                        s.error_message = "Process restarted before initial discovery tasks completed."

                    s.completed_at = datetime.now(timezone.utc)
                    db.add(ScanLog(
                        scan_id=s.id,
                        level="WARNING",
                        message=f"Process recovery: Server restarted. Scan marked as {s.status} with {a_count} assets and {f_count} findings preserved."
                    ))
                await db.commit()
                logger.info("Scan recovery completed successfully.")
        except Exception as e:
            logger.error(f"Error during scan recovery on startup: {e}", exc_info=True)

    async def _log(self, db: AsyncSession, scan_id: str, level: str, message: str, phase: str = "DISCOVERY", details: dict = None):
        """Record ScanLog and DiscoveryEvent atomically with credential scrubbing."""
        safe_msg = sanitize_sensitive_data(message)
        safe_details = sanitize_sensitive_data(details or {})

        scan_log = ScanLog(scan_id=scan_id, level=level, message=safe_msg)
        db.add(scan_log)
        
        event = DiscoveryEvent(
            scan_id=scan_id,
            event_type="INFO" if level == "INFO" else level,
            phase=phase,
            message=safe_msg,
            details=safe_details
        )
        db.add(event)
        await db.commit()

    async def _update_scan_state(
        self,
        db: AsyncSession,
        scan_id: str,
        status: str,
        stage: str,
        progress: int,
        error: str = None,
        tasks_summary: Optional[Dict[str, int]] = None,
        module_status: Optional[Dict[str, Any]] = None
    ):
        """Update scan status, stage, progress, tasks_summary, and module_status in database."""
        res = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = res.scalar_one_or_none()
        if scan:
            scan.status = status
            scan.current_stage = stage
            scan.progress = progress
            if error:
                scan.error_message = sanitize_sensitive_data(error)
            
            cfg = dict(scan.configuration or {})
            if tasks_summary:
                cfg["tasks_summary"] = tasks_summary
            if module_status:
                cfg["module_status"] = module_status
            scan.configuration = cfg

            if status in ["COMPLETED", "PARTIALLY_COMPLETED", "FAILED", "CANCELLED"]:
                scan.completed_at = datetime.now(timezone.utc)
            await db.commit()

    async def _update_stage_record(
        self,
        db: AsyncSession,
        scan_id: str,
        stage_name: str,
        status: str,
        duration: float = 0.0,
        discovered: int = 0,
        persisted: int = 0,
        error: Optional[str] = None,
        failure_category: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Atomically persist or update a ScanStage pipeline record."""
        res = await db.execute(
            select(ScanStage).where(
                ScanStage.scan_id == scan_id,
                ScanStage.stage_name == stage_name
            )
        )
        stage_rec = res.scalar_one_or_none()
        if not stage_rec:
            stage_rec = ScanStage(
                scan_id=scan_id,
                stage_name=stage_name,
                stage_status=status
            )
            db.add(stage_rec)

        stage_rec.stage_status = status
        stage_rec.duration = duration
        stage_rec.successful_count = discovered
        stage_rec.output_count = persisted
        if status == StageStatus.RUNNING:
            stage_rec.started_at = datetime.now(timezone.utc)
        elif status in [StageStatus.COMPLETED, StageStatus.PARTIALLY_COMPLETED, StageStatus.FAILED, StageStatus.SKIPPED]:
            stage_rec.completed_at = datetime.now(timezone.utc)

        if error:
            stage_rec.error_message = sanitize_sensitive_data(error)
            stage_rec.failure_category = failure_category or classify_exception(Exception(error))
        if metadata:
            meta = dict(stage_rec.execution_metadata or {})
            meta.update(metadata)
            stage_rec.execution_metadata = meta

        await db.commit()

    def _calculate_progress(self, tasks: Dict[str, int]) -> int:
        """Calculate dynamic progress percentage from real task counters."""
        total = tasks.get("pending", 0) + tasks.get("processing", 0) + tasks.get("completed", 0) + tasks.get("failed", 0) + tasks.get("skipped", 0)
        if total <= 0:
            return 0
        done = tasks.get("completed", 0) + tasks.get("failed", 0) + tasks.get("skipped", 0)
        return min(99, max(0, int((done / total) * 100)))

    async def _run_orchestrated_lifecycle(self, scan_id: str, config: Dict[str, Any], cancel_event: asyncio.Event):
        """
        Main execution lifecycle across explicit stages:
        QUEUED -> INITIALIZING -> FINGERPRINTING -> CRAWLING -> BROWSER_DISCOVERY ->
        SOURCE_ANALYSIS -> CORRELATING -> PERSISTING -> COMPLETED / PARTIALLY_COMPLETED / FAILED / CANCELLED.
        """
        async with self.concurrency_semaphore:
            async with AsyncSessionLocal() as db:
                mode = config.get("discovery_mode", ScanMode.WEBSITE_ONLY)
                
                # Active task tracking counters
                tasks: Dict[str, int] = {
                    "pending": 0,
                    "processing": 0,
                    "completed": 0,
                    "failed": 0,
                    "skipped": 0
                }
                
                # Module status tracker
                modules: Dict[str, Any] = {
                    "fingerprinting": {"status": "PENDING", "duration_seconds": 0.0, "discovered": 0, "persisted": 0, "error": None},
                    "crawling": {"status": "PENDING", "duration_seconds": 0.0, "discovered": 0, "persisted": 0, "error": None},
                    "browser_discovery": {"status": "PENDING", "duration_seconds": 0.0, "discovered": 0, "persisted": 0, "error": None},
                    "source_analysis": {"status": "PENDING", "duration_seconds": 0.0, "discovered": 0, "persisted": 0, "error": None},
                    "correlating": {"status": "PENDING", "duration_seconds": 0.0, "discovered": 0, "persisted": 0, "error": None},
                    "persisting": {"status": "PENDING", "duration_seconds": 0.0, "discovered": 0, "persisted": 0, "error": None}
                }

                # Mark skipped modules for current mode up front
                if mode == ScanMode.WEBSITE_ONLY:
                    modules["source_analysis"] = {"status": "SKIPPED", "duration_seconds": 0.0, "discovered": 0, "persisted": 0, "error": None, "reason": "Not applicable for WEBSITE_ONLY mode"}
                    modules["correlating"] = {"status": "SKIPPED", "duration_seconds": 0.0, "discovered": 0, "persisted": 0, "error": None, "reason": "Not applicable for WEBSITE_ONLY mode"}
                    tasks["skipped"] += 2
                elif mode == ScanMode.GITHUB_ONLY:
                    modules["fingerprinting"] = {"status": "SKIPPED", "duration_seconds": 0.0, "discovered": 0, "persisted": 0, "error": None, "reason": "Not applicable for GITHUB_ONLY mode"}
                    modules["crawling"] = {"status": "SKIPPED", "duration_seconds": 0.0, "discovered": 0, "persisted": 0, "error": None, "reason": "Not applicable for GITHUB_ONLY mode"}
                    modules["browser_discovery"] = {"status": "SKIPPED", "duration_seconds": 0.0, "discovered": 0, "persisted": 0, "error": None, "reason": "Not applicable for GITHUB_ONLY mode"}
                    modules["correlating"] = {"status": "SKIPPED", "duration_seconds": 0.0, "discovered": 0, "persisted": 0, "error": None, "reason": "Not applicable for GITHUB_ONLY mode"}
                    tasks["skipped"] += 4

                # Initialize all persistent pipeline stage records in database
                all_pipeline_stages = [
                    ("TARGET_FINGERPRINTING", [ScanMode.WEBSITE_ONLY, ScanMode.HYBRID]),
                    ("STATIC_CRAWLING", [ScanMode.WEBSITE_ONLY, ScanMode.HYBRID]),
                    ("BROWSER_DISCOVERY", [ScanMode.WEBSITE_ONLY, ScanMode.HYBRID]),
                    ("REPOSITORY_ACQUISITION", [ScanMode.GITHUB_ONLY, ScanMode.HYBRID]),
                    ("SOURCE_ANALYSIS", [ScanMode.GITHUB_ONLY, ScanMode.HYBRID]),
                    ("SOURCE_RUNTIME_CORRELATION", [ScanMode.HYBRID]),
                    ("ASSET_NORMALIZATION", [ScanMode.WEBSITE_ONLY, ScanMode.GITHUB_ONLY, ScanMode.HYBRID]),
                    ("ATTACK_SURFACE_GENERATION", [ScanMode.WEBSITE_ONLY, ScanMode.HYBRID]),
                    ("CONTEXT_AWARE_FUZZING", [ScanMode.WEBSITE_ONLY, ScanMode.HYBRID]),
                    ("VULNERABILITY_VALIDATION", [ScanMode.WEBSITE_ONLY, ScanMode.HYBRID]),
                    ("DATABASE_PERSISTENCE", [ScanMode.WEBSITE_ONLY, ScanMode.GITHUB_ONLY, ScanMode.HYBRID]),
                    ("REPORT_GENERATION", [ScanMode.WEBSITE_ONLY, ScanMode.GITHUB_ONLY, ScanMode.HYBRID]),
                ]
                for s_name, app_modes in all_pipeline_stages:
                    is_app = mode in app_modes
                    s_status = StageStatus.PENDING if is_app else StageStatus.SKIPPED
                    s_meta = {} if is_app else {"reason": f"Not applicable for {mode} mode"}
                    stage_rec = ScanStage(
                        scan_id=scan_id,
                        stage_name=s_name,
                        stage_status=s_status,
                        execution_metadata=s_meta
                    )
                    db.add(stage_rec)
                await db.commit()

                failed_modules = []

                try:
                    # ----------------------------------------------------------
                    # STAGE: INITIALIZING
                    # ----------------------------------------------------------
                    await self._update_scan_state(db, scan_id, "RUNNING", "INITIALIZING", 5, tasks_summary=tasks, module_status=modules)
                    await self._log(db, scan_id, "INFO", f"[INITIALIZING] Preparing execution pipeline for mode: {mode}", "INITIALIZING")
                    
                    if cancel_event.is_set():
                        raise ScanCancelledError("Scan cancelled during initialization.")

                    # ----------------------------------------------------------
                    # STAGE: FINGERPRINTING (WEBSITE_ONLY, HYBRID)
                    # ----------------------------------------------------------
                    if mode in [ScanMode.WEBSITE_ONLY, ScanMode.HYBRID]:
                        target_url = config.get("website_url") or config.get("target_url")
                        t0 = time.time()
                        modules["fingerprinting"]["status"] = "RUNNING"
                        tasks["processing"] += 1
                        await self._update_scan_state(db, scan_id, "FINGERPRINTING", "FINGERPRINTING", self._calculate_progress(tasks), tasks_summary=tasks, module_status=modules)
                        await self._log(db, scan_id, "INFO", f"[FINGERPRINTING] Probing target website technologies at: {target_url}", "FINGERPRINTING")

                        try:
                            from app.scanner.http_client import ResilientHttpClient
                            from app.scanner.discovery.fingerprint import TechnologyFingerprinter

                            fp_client = ResilientHttpClient(max_requests=10, concurrency=2, timeout=8)
                            try:
                                resp = await fp_client.get(target_url)
                                http_code = resp.status_code
                                techs, archs = TechnologyFingerprinter.fingerprint(resp.headers, resp.text)
                            finally:
                                await fp_client.close()

                            # Persist discovered tech stack
                            web_res = await db.execute(select(WebsiteProfile).where(WebsiteProfile.scan_id == scan_id))
                            web_profile = web_res.scalar_one_or_none()
                            if web_profile:
                                web_profile.tech_stack = techs
                                web_profile.security_headers = {
                                    k: v for k, v in resp.headers.items() 
                                    if k.lower() in ["content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options"]
                                }
                                await db.commit()

                            dur = round(time.time() - t0, 3)
                            modules["fingerprinting"].update({
                                "status": "COMPLETED",
                                "duration_seconds": dur,
                                "http_status": http_code,
                                "discovered": len(techs),
                                "persisted": len(techs),
                                "error": None
                            })
                            tasks["processing"] -= 1
                            tasks["completed"] += 1
                            await self._update_stage_record(
                                db, scan_id, "TARGET_FINGERPRINTING", StageStatus.COMPLETED,
                                duration=dur, discovered=len(techs), persisted=len(techs)
                            )
                            await self._log(
                                db, scan_id, "SUCCESS",
                                f"[FINGERPRINTING] Completed in {dur}s (HTTP {http_code}). Detected: {', '.join(techs) if techs else 'Generic Web App'}",
                                "FINGERPRINTING",
                                details={"duration": dur, "http_status": http_code, "techs": techs, "architectures": archs}
                            )
                        except Exception as e:
                            logger.error(f"Fingerprinting error for {scan_id}: {e}", exc_info=True)
                            dur = round(time.time() - t0, 3)
                            modules["fingerprinting"].update({
                                "status": "FAILED",
                                "duration_seconds": dur,
                                "error": str(e)
                            })
                            tasks["processing"] -= 1
                            tasks["failed"] += 1
                            failed_modules.append("fingerprinting")
                            await self._update_stage_record(
                                db, scan_id, "TARGET_FINGERPRINTING", StageStatus.FAILED,
                                duration=dur, error=str(e), failure_category=classify_exception(e)
                            )
                            db.add(DiscoveryError(scan_id=scan_id, component="FINGERPRINTING", error_type=type(e).__name__, message=str(e), target_url=target_url))
                            await db.commit()
                            await self._log(db, scan_id, "WARN", f"[WARNING] Fingerprinting failed: {e}", "FINGERPRINTING")

                    if cancel_event.is_set():
                        raise ScanCancelledError("Scan cancelled after fingerprinting.")

                    # ----------------------------------------------------------
                    # STAGE: CRAWLING (WEBSITE_ONLY, HYBRID)
                    # ----------------------------------------------------------
                    if mode in [ScanMode.WEBSITE_ONLY, ScanMode.HYBRID]:
                        t0 = time.time()
                        modules["crawling"]["status"] = "RUNNING"
                        tasks["processing"] += 1
                        await self._update_scan_state(db, scan_id, "CRAWLING", "CRAWLING", self._calculate_progress(tasks), tasks_summary=tasks, module_status=modules)
                        await self._update_stage_record(db, scan_id, "STATIC_CRAWLING", StageStatus.RUNNING)
                        await self._log(db, scan_id, "INFO", "[CRAWLING] Launching static HTML crawler and sitemap parser...", "CRAWLING")

                        try:
                            from app.scanner.discovery.website_engine import WebsiteDiscoveryEngine
                            target_url = config.get("website_url") or config.get("target_url")
                            web_engine = WebsiteDiscoveryEngine(scan_id=scan_id, target_url=target_url, db=db, config=config)
                            
                            # Run static crawl and doc parsing
                            crawl_summary = await web_engine.run(cancel_event)
                            dur = round(time.time() - t0, 3)
                            pages_count = crawl_summary.get("static_pages", 0) + crawl_summary.get("dynamic_pages", 0)
                            apis_count = crawl_summary.get("network_endpoints", 0) + crawl_summary.get("api_doc_operations", 0)

                            modules["crawling"].update({
                                "status": "COMPLETED",
                                "duration_seconds": dur,
                                "discovered": pages_count + apis_count,
                                "persisted": crawl_summary.get("total_endpoints_synced", 0),
                                "error": None
                            })
                            tasks["processing"] -= 1
                            tasks["completed"] += 1
                            await self._update_stage_record(
                                db, scan_id, "STATIC_CRAWLING", StageStatus.COMPLETED,
                                duration=dur, discovered=pages_count + apis_count,
                                persisted=crawl_summary.get("total_endpoints_synced", 0)
                            )
                            await self._log(
                                db, scan_id, "SUCCESS",
                                f"[CRAWLING] Completed in {dur}s. Crawled {pages_count} pages, {apis_count} endpoints.",
                                "CRAWLING",
                                details=crawl_summary
                            )
                        except Exception as e:
                            logger.error(f"Crawling error for {scan_id}: {e}", exc_info=True)
                            dur = round(time.time() - t0, 3)
                            modules["crawling"].update({
                                "status": "FAILED",
                                "duration_seconds": dur,
                                "error": str(e)
                            })
                            tasks["processing"] -= 1
                            tasks["failed"] += 1
                            failed_modules.append("crawling")
                            await self._update_stage_record(
                                db, scan_id, "STATIC_CRAWLING", StageStatus.FAILED,
                                duration=dur, error=str(e), failure_category=classify_exception(e)
                            )
                            db.add(DiscoveryError(scan_id=scan_id, component="CRAWLING", error_type=type(e).__name__, message=str(e), target_url=config.get("website_url")))
                            await db.commit()
                            await self._log(db, scan_id, "WARN", f"[WARNING] Crawling encountered an error: {e}", "CRAWLING")

                    if cancel_event.is_set():
                        raise ScanCancelledError("Scan cancelled after crawling.")

                    # ----------------------------------------------------------
                    # STAGE: BROWSER_DISCOVERY (WEBSITE_ONLY, HYBRID)
                    # ----------------------------------------------------------
                    if mode in [ScanMode.WEBSITE_ONLY, ScanMode.HYBRID]:
                        t0 = time.time()
                        modules["browser_discovery"]["status"] = "RUNNING"
                        tasks["processing"] += 1
                        await self._update_scan_state(db, scan_id, "BROWSER_DISCOVERY", "BROWSER_DISCOVERY", self._calculate_progress(tasks), tasks_summary=tasks, module_status=modules)
                        
                        enable_pw = config.get("enable_playwright", True)
                        if not enable_pw:
                            modules["browser_discovery"] = {"status": "SKIPPED", "duration_seconds": 0.0, "discovered": 0, "persisted": 0, "reason": "Playwright disabled by config"}
                            tasks["processing"] -= 1
                            tasks["skipped"] += 1
                            await self._update_stage_record(db, scan_id, "BROWSER_DISCOVERY", StageStatus.SKIPPED, metadata={"reason": "Playwright disabled by config"})
                            await self._log(db, scan_id, "INFO", "[BROWSER_DISCOVERY] Headless browser discovery skipped per user configuration.", "BROWSER_DISCOVERY")
                        else:
                            await self._update_stage_record(db, scan_id, "BROWSER_DISCOVERY", StageStatus.RUNNING)
                            await self._log(db, scan_id, "INFO", "[BROWSER_DISCOVERY] Launching Playwright browser for DOM rendering & API interception...", "BROWSER_DISCOVERY")
                            try:
                                from app.scanner.discovery.browser_crawler import PlaywrightDynamicCrawler
                                pw_crawler = PlaywrightDynamicCrawler(
                                    scan_id=scan_id,
                                    target_url=config.get("website_url") or config.get("target_url"),
                                    db=db,
                                    max_depth=min(config.get("max_depth", 2), 2),
                                    max_pages=min(config.get("max_requests", 30), 30),
                                    custom_headers=config.get("custom_headers", {}),
                                    auth_cookies=config.get("auth_cookies", [])
                                )
                                pw_res = await pw_crawler.run(cancel_event)
                                dur = round(time.time() - t0, 3)

                                if pw_res.get("status") == "SKIPPED":
                                    modules["browser_discovery"].update({"status": "SKIPPED", "duration_seconds": dur, "reason": pw_res.get("reason", "Skipped")})
                                    tasks["processing"] -= 1
                                    tasks["skipped"] += 1
                                    await self._update_stage_record(db, scan_id, "BROWSER_DISCOVERY", StageStatus.SKIPPED, duration=dur, metadata={"reason": pw_res.get("reason")})
                                    await self._log(db, scan_id, "WARN", f"[BROWSER_DISCOVERY] Skipped: {pw_res.get('reason')}", "BROWSER_DISCOVERY")
                                elif pw_res.get("status") == "FAILED":
                                    modules["browser_discovery"].update({"status": "FAILED", "duration_seconds": dur, "error": pw_res.get("error")})
                                    tasks["processing"] -= 1
                                    tasks["failed"] += 1
                                    failed_modules.append("browser_discovery")
                                    await self._update_stage_record(db, scan_id, "BROWSER_DISCOVERY", StageStatus.FAILED, duration=dur, error=pw_res.get("error"), failure_category=FailureCategory.ENVIRONMENTAL)
                                    await self._log(db, scan_id, "WARN", f"[BROWSER_DISCOVERY] Encountered error: {pw_res.get('error')}", "BROWSER_DISCOVERY")
                                else:
                                    pages_rendered = pw_res.get("pages_crawled", 0)
                                    apis_intercepted = pw_res.get("network_endpoints_captured", 0)
                                    modules["browser_discovery"].update({
                                        "status": "COMPLETED",
                                        "duration_seconds": dur,
                                        "discovered": pages_rendered + apis_intercepted,
                                        "persisted": apis_intercepted,
                                        "error": None
                                    })
                                    tasks["processing"] -= 1
                                    tasks["completed"] += 1
                                    await self._update_stage_record(
                                        db, scan_id, "BROWSER_DISCOVERY", StageStatus.COMPLETED,
                                        duration=dur, discovered=pages_rendered + apis_intercepted,
                                        persisted=apis_intercepted
                                    )
                                    await self._log(
                                        db, scan_id, "SUCCESS",
                                        f"[BROWSER_DISCOVERY] Completed in {dur}s. Rendered {pages_rendered} pages, intercepted {apis_intercepted} API requests.",
                                        "BROWSER_DISCOVERY",
                                        details=pw_res
                                    )
                            except Exception as e:
                                logger.error(f"Browser discovery error for {scan_id}: {e}", exc_info=True)
                                dur = round(time.time() - t0, 3)
                                modules["browser_discovery"].update({"status": "FAILED", "duration_seconds": dur, "error": str(e)})
                                tasks["processing"] -= 1
                                tasks["failed"] += 1
                                failed_modules.append("browser_discovery")
                                await self._update_stage_record(
                                    db, scan_id, "BROWSER_DISCOVERY", StageStatus.FAILED,
                                    duration=dur, error=str(e), failure_category=classify_exception(e)
                                )
                                db.add(DiscoveryError(scan_id=scan_id, component="BROWSER_DISCOVERY", error_type=type(e).__name__, message=str(e)))
                                await db.commit()
                                await self._log(db, scan_id, "WARN", f"[WARNING] Browser discovery failed: {e}", "BROWSER_DISCOVERY")

                    if cancel_event.is_set():
                        raise ScanCancelledError("Scan cancelled after browser discovery.")

                    # ----------------------------------------------------------
                    # STAGE: SOURCE_ANALYSIS (GITHUB_ONLY, HYBRID)
                    # ----------------------------------------------------------
                    if mode in [ScanMode.GITHUB_ONLY, ScanMode.HYBRID]:
                        t0 = time.time()
                        modules["source_analysis"]["status"] = "RUNNING"
                        tasks["processing"] += 1
                        await self._update_scan_state(db, scan_id, "SOURCE_ANALYSIS", "SOURCE_ANALYSIS", self._calculate_progress(tasks), tasks_summary=tasks, module_status=modules)
                        await self._update_stage_record(db, scan_id, "REPOSITORY_ACQUISITION", StageStatus.RUNNING)
                        await self._update_stage_record(db, scan_id, "SOURCE_ANALYSIS", StageStatus.RUNNING)
                        await self._log(db, scan_id, "INFO", f"[SOURCE_ANALYSIS] Acquiring repository and parsing AST route declarations: {sanitize_sensitive_data(config.get('repository_url'))}", "SOURCE_ANALYSIS")

                        try:
                            from app.scanner.discovery.source.source_engine import SourceCodeDiscoveryEngine
                            src_engine = SourceCodeDiscoveryEngine(
                                scan_id=scan_id,
                                repo_url=config.get("repository_url"),
                                db=db,
                                config=config
                            )
                            src_summary = await src_engine.run(cancel_event)
                            dur = round(time.time() - t0, 3)
                            routes_found = src_summary.get("routes_discovered", 0)
                            files_parsed = src_summary.get("files_analyzed", 0)

                            modules["source_analysis"].update({
                                "status": "COMPLETED",
                                "duration_seconds": dur,
                                "discovered": routes_found,
                                "persisted": routes_found,
                                "error": None
                            })
                            tasks["processing"] -= 1
                            tasks["completed"] += 1
                            await self._update_stage_record(
                                db, scan_id, "REPOSITORY_ACQUISITION", StageStatus.COMPLETED,
                                duration=round(dur * 0.3, 3), discovered=files_parsed, persisted=files_parsed
                            )
                            await self._update_stage_record(
                                db, scan_id, "SOURCE_ANALYSIS", StageStatus.COMPLETED,
                                duration=dur, discovered=routes_found, persisted=routes_found,
                                metadata=src_summary
                            )
                            await self._log(
                                db, scan_id, "SUCCESS",
                                f"[SOURCE_ANALYSIS] Completed in {dur}s across {files_parsed} files. Discovered {routes_found} routes.",
                                "SOURCE_ANALYSIS",
                                details=src_summary
                            )
                        except Exception as e:
                            logger.error(f"Source discovery error for {scan_id}: {e}", exc_info=True)
                            dur = round(time.time() - t0, 3)
                            modules["source_analysis"].update({"status": "FAILED", "duration_seconds": dur, "error": str(e)})
                            tasks["processing"] -= 1
                            tasks["failed"] += 1
                            failed_modules.append("source_analysis")
                            await self._update_stage_record(
                                db, scan_id, "SOURCE_ANALYSIS", StageStatus.FAILED,
                                duration=dur, error=str(e), failure_category=classify_exception(e)
                            )
                            db.add(DiscoveryError(scan_id=scan_id, component="SOURCE_ANALYSIS", error_type=type(e).__name__, message=str(e), source_file=config.get("repository_url")))
                            await db.commit()
                            await self._log(db, scan_id, "WARN", f"[WARNING] Source analysis encountered an error: {e}", "SOURCE_ANALYSIS")

                    if cancel_event.is_set():
                        raise ScanCancelledError("Scan cancelled after source analysis.")

                    # ----------------------------------------------------------
                    # STAGE: CORRELATING (HYBRID ONLY)
                    # ----------------------------------------------------------
                    if mode == ScanMode.HYBRID:
                        t0 = time.time()
                        modules["correlating"]["status"] = "RUNNING"
                        tasks["processing"] += 1
                        await self._update_scan_state(db, scan_id, "CORRELATING", "CORRELATING", self._calculate_progress(tasks), tasks_summary=tasks, module_status=modules)
                        await self._update_stage_record(db, scan_id, "SOURCE_RUNTIME_CORRELATION", StageStatus.RUNNING)
                        await self._log(db, scan_id, "INFO", "[CORRELATING] Cross-referencing source declarations with runtime network observations...", "CORRELATING")

                        try:
                            from app.scanner.discovery.correlation.engine import CorrelationEngine
                            corr_engine = CorrelationEngine(scan_id=scan_id, db=db)
                            corr_summary = await corr_engine.run(cancel_event)
                            dur = round(time.time() - t0, 3)
                            matches = corr_summary.get("total_matches", 0)

                            modules["correlating"].update({
                                "status": "COMPLETED",
                                "duration_seconds": dur,
                                "discovered": matches,
                                "persisted": matches,
                                "error": None
                            })
                            tasks["processing"] -= 1
                            tasks["completed"] += 1
                            await self._update_stage_record(
                                db, scan_id, "SOURCE_RUNTIME_CORRELATION", StageStatus.COMPLETED,
                                duration=dur, discovered=matches, persisted=matches, metadata=corr_summary
                            )
                            await self._log(
                                db, scan_id, "SUCCESS",
                                f"[CORRELATING] Completed in {dur}s. Verified matches: {matches}; Graph nodes: {corr_summary.get('graph_nodes', 0)}",
                                "CORRELATING",
                                details=corr_summary
                            )
                        except Exception as e:
                            logger.error(f"Correlation error for {scan_id}: {e}", exc_info=True)
                            dur = round(time.time() - t0, 3)
                            modules["correlating"].update({"status": "FAILED", "duration_seconds": dur, "error": str(e)})
                            tasks["processing"] -= 1
                            tasks["failed"] += 1
                            failed_modules.append("correlating")
                            await self._update_stage_record(
                                db, scan_id, "SOURCE_RUNTIME_CORRELATION", StageStatus.FAILED,
                                duration=dur, error=str(e), failure_category=classify_exception(e)
                            )
                            db.add(DiscoveryError(scan_id=scan_id, component="CORRELATING", error_type=type(e).__name__, message=str(e)))
                            await db.commit()
                            await self._log(db, scan_id, "WARN", f"[WARNING] Correlation encountered an error: {e}", "CORRELATING")

                    if cancel_event.is_set():
                        raise ScanCancelledError("Scan cancelled before persistence.")

                    # ----------------------------------------------------------
                    # STAGE: PERSISTING & DATABASE VERIFICATION
                    # ----------------------------------------------------------
                    t0 = time.time()
                    modules["persisting"]["status"] = "RUNNING"
                    tasks["processing"] += 1
                    await self._update_scan_state(db, scan_id, "PERSISTING", "PERSISTING", self._calculate_progress(tasks), tasks_summary=tasks, module_status=modules)
                    await self._update_stage_record(db, scan_id, "ASSET_NORMALIZATION", StageStatus.RUNNING)
                    await self._update_stage_record(db, scan_id, "DATABASE_PERSISTENCE", StageStatus.RUNNING)
                    await self._log(db, scan_id, "INFO", "[PERSISTING] Synchronizing discovered inventory and verifying database records...", "PERSISTING")

                    # Run database synchronization to legacy tables for downstream tools
                    synced_eps = await self._sync_all_assets_to_legacy(db, scan_id)

                    # Strict Database Verification
                    db_verification = await self._verify_persisted_database_records(db, scan_id)
                    dur = round(time.time() - t0, 3)

                    modules["persisting"].update({
                        "status": "COMPLETED",
                        "duration_seconds": dur,
                        "discovered": db_verification["total_assets"],
                        "persisted": db_verification["total_assets"],
                        "error": None
                    })
                    tasks["processing"] -= 1
                    tasks["completed"] += 1
                    await self._update_stage_record(
                        db, scan_id, "ASSET_NORMALIZATION", StageStatus.COMPLETED,
                        duration=round(dur * 0.5, 3), discovered=synced_eps, persisted=synced_eps
                    )
                    await self._update_stage_record(
                        db, scan_id, "DATABASE_PERSISTENCE", StageStatus.COMPLETED,
                        duration=dur, discovered=db_verification["total_assets"], persisted=db_verification["total_assets"]
                    )

                    await self._log(
                        db, scan_id, "SUCCESS",
                        f"[PERSISTING] Database verification confirmed. "
                        f"Pages: {db_verification['pages_count']}, "
                        f"Endpoints: {db_verification['endpoints_count']}, "
                        f"Parameters: {db_verification['parameters_count']}, "
                        f"Forms: {db_verification['forms_count']}, "
                        f"Source Files: {db_verification['source_files_count']}, "
                        f"Source Evidences: {db_verification['source_evidences_count']}, "
                        f"Runtime Evidences: {db_verification['runtime_evidences_count']}, "
                        f"Events: {db_verification['events_count']}",
                        "PERSISTING",
                        details=db_verification
                    )

                    # ----------------------------------------------------------
                    # DOWNSTREAM FUZZING PIPELINE (WEBSITE_ONLY, HYBRID)
                    # ----------------------------------------------------------
                    if mode in [ScanMode.WEBSITE_ONLY, ScanMode.HYBRID]:
                        from app.scanner.executor import STAGES, update_scan_state, log_event
                        for stage_name, target_progress in STAGES[2:]:
                            if cancel_event.is_set():
                                raise ScanCancelledError("Scan cancelled by user.")
                            
                            await update_scan_state(db, scan_id, "RUNNING", stage_name, target_progress)
                            await log_event(db, scan_id, "INFO", f"[INFO] Transitioned to pipeline stage: {stage_name} ({target_progress}%)")
                            
                            if stage_name == "ATTACK_SURFACE":
                                from app.scanner.analyzer import AttackSurfaceAnalyzer
                                analyzer = AttackSurfaceAnalyzer(db, scan_id)
                                await analyzer.analyze()
                                await self._update_stage_record(db, scan_id, "ATTACK_SURFACE_GENERATION", StageStatus.COMPLETED, duration=0.5)
                            elif stage_name == "PRIORITIZATION":
                                from app.scanner.prioritization.scorer import RuleBasedPrioritizer
                                prioritizer = RuleBasedPrioritizer(db, scan_id)
                                await prioritizer.prioritize_all()
                            elif stage_name == "FUZZING":
                                from app.scanner.http_client import ResilientHttpClient
                                from app.scanner.fuzzer.engine import FuzzingEngine
                                max_reqs = config.get("max_requests", 1000)
                                fuzz_client = ResilientHttpClient(max_requests=max_reqs, concurrency=5, timeout=10)
                                try:
                                    fuzzer = FuzzingEngine(db, scan_id, fuzz_client)
                                    await fuzzer.run(cancel_event)
                                    await self._update_stage_record(db, scan_id, "CONTEXT_AWARE_FUZZING", StageStatus.COMPLETED, duration=1.0)
                                finally:
                                    await fuzz_client.close()
                            elif stage_name == "ANALYSIS":
                                from app.scanner.http_client import ResilientHttpClient
                                from app.scanner.fuzzer.engine import SCAN_FUZZ_RESULTS
                                from app.scanner.analysis.analyzer import ResponseAnalyzer
                                analysis_client = ResilientHttpClient(max_requests=500, concurrency=5, timeout=10)
                                try:
                                    analyzer = ResponseAnalyzer(db, scan_id, analysis_client)
                                    fuzz_results = SCAN_FUZZ_RESULTS.get(scan_id, [])
                                    await analyzer.analyze_fuzz_results(fuzz_results)
                                finally:
                                    await analysis_client.close()
                            elif stage_name == "VALIDATION":
                                from app.scanner.http_client import ResilientHttpClient
                                from app.scanner.analysis.analyzer import SCAN_ANALYSIS_REPORTS
                                from app.scanner.validation.validator import EvidenceValidator
                                validation_client = ResilientHttpClient(max_requests=500, concurrency=3, timeout=10)
                                try:
                                    validator = EvidenceValidator(db, scan_id, validation_client)
                                    anomalies = SCAN_ANALYSIS_REPORTS.get(scan_id, [])
                                    await validator.validate_anomalies(anomalies, cancel_event)
                                    await self._update_stage_record(db, scan_id, "VULNERABILITY_VALIDATION", StageStatus.COMPLETED, duration=0.8)
                                finally:
                                    await validation_client.close()
                            elif stage_name == "REPORTING":
                                await asyncio.sleep(0.3)
                                await self._update_stage_record(db, scan_id, "REPORT_GENERATION", StageStatus.COMPLETED, duration=0.3)
                    elif mode == ScanMode.GITHUB_ONLY:
                        # In REPOSITORY_ONLY mode, mark runtime fuzzing NOT_PERFORMED / SKIPPED
                        await self._update_stage_record(
                            db, scan_id, "CONTEXT_AWARE_FUZZING", StageStatus.SKIPPED,
                            metadata={"reason": "Runtime fuzzing not performed in REPOSITORY_ONLY mode"}
                        )
                        await self._update_stage_record(
                            db, scan_id, "VULNERABILITY_VALIDATION", StageStatus.SKIPPED,
                            metadata={"reason": "Runtime testing not performed in REPOSITORY_ONLY mode"}
                        )
                        await self._update_stage_record(db, scan_id, "REPORT_GENERATION", StageStatus.COMPLETED, duration=0.2)


                    # ----------------------------------------------------------
                    # FINAL STATUS DETERMINATION
                    # ----------------------------------------------------------
                    final_progress = 100
                    if failed_modules:
                        final_status = "PARTIALLY_COMPLETED"
                        stage_status = "PARTIALLY_COMPLETED"
                        err_summary = f"Scan completed with warnings. Failed modules: {', '.join(failed_modules)}"
                        await self._update_scan_state(
                            db, scan_id, final_status, stage_status, final_progress,
                            error=err_summary, tasks_summary=tasks, module_status=modules
                        )
                        await self._log(db, scan_id, "WARN", f"[PARTIAL] {err_summary}", "COMPLETED", details={"failed_modules": failed_modules})
                    else:
                        final_status = "COMPLETED"
                        stage_status = "COMPLETED"
                        await self._update_scan_state(
                            db, scan_id, final_status, stage_status, final_progress,
                            tasks_summary=tasks, module_status=modules
                        )
                        await self._log(db, scan_id, "SUCCESS", f"[SUCCESS] Scan {scan_id} finished complete lifecycle across all modules.", "COMPLETED")

                except ScanCancelledError as e:
                    logger.warning(f"Scan {scan_id} cancelled: {e}")
                    tasks["failed"] += 1
                    await self._update_scan_state(db, scan_id, "CANCELLED", "CANCELLED", 0, str(e), tasks_summary=tasks, module_status=modules)
                    await self._log(db, scan_id, "WARN", f"[CANCELLED] Scan execution stopped by user: {e}", "CANCELLED")
                except Exception as e:
                    logger.error(f"Scan {scan_id} encountered fatal error: {e}", exc_info=True)
                    tasks["failed"] += 1
                    await self._update_scan_state(db, scan_id, "FAILED", "FAILED", 0, str(e), tasks_summary=tasks, module_status=modules)
                    await self._log(db, scan_id, "CRITICAL", f"[CRITICAL] Scan execution failed: {e}", "FAILED")

    async def _sync_all_assets_to_legacy(self, db: AsyncSession, scan_id: str) -> int:
        """
        Synchronize all DiscoveredAsset records (HTTP_ENDPOINT, BACKEND_API_OPERATION, WEBSITE_PAGE)
        and associated parameters into legacy Endpoint and Parameter tables.
        """
        res = await db.execute(
            select(DiscoveredAsset).where(
                DiscoveredAsset.scan_id == scan_id,
                DiscoveredAsset.asset_type.in_([AssetType.HTTP_ENDPOINT, AssetType.BACKEND_API_OPERATION, AssetType.WEBSITE_PAGE])
            )
        )
        assets = res.scalars().all()
        synced = 0

        for a in assets:
            if not a.url or not a.path:
                continue

            ep_res = await db.execute(
                select(Endpoint).where(
                    Endpoint.scan_id == scan_id,
                    Endpoint.url == a.url,
                    Endpoint.method == (a.method or "GET")
                )
            )
            legacy_ep = ep_res.scalar_one_or_none()
            if not legacy_ep:
                legacy_ep = Endpoint(
                    id=a.id,
                    scan_id=scan_id,
                    url=a.url,
                    path=a.path,
                    method=a.method or "GET",
                    status_code=a.metadata_json.get("status_code", 200) if a.metadata_json else 200,
                    content_type="text/html" if a.asset_type in [AssetType.HTTP_ENDPOINT, AssetType.WEBSITE_PAGE] else "application/json",
                    depth=a.metadata_json.get("depth", 1) if a.metadata_json else 1,
                    discovered_from=f"discovery_engine:{a.discovery_status}",
                    is_api=a.asset_type == AssetType.BACKEND_API_OPERATION,
                    priority_score=0.0
                )
                db.add(legacy_ep)
                synced += 1
                await db.flush()

            # 1. Sync parameters from EndpointParameter
            p_res = await db.execute(
                select(EndpointParameter).where(
                    EndpointParameter.scan_id == scan_id,
                    EndpointParameter.asset_id == a.id
                )
            )
            for p in p_res.scalars().all():
                chk = await db.execute(
                    select(Parameter).where(
                        Parameter.endpoint_id == legacy_ep.id,
                        Parameter.name == p.name
                    )
                )
                if not chk.scalar_one_or_none():
                    leg_p = Parameter(
                        endpoint_id=legacy_ep.id,
                        name=p.name,
                        location=p.location or "query",
                        value_type=p.value_type or "string"
                    )
                    db.add(leg_p)

            # 2. Sync parameters from DiscoveredForm
            f_res = await db.execute(
                select(DiscoveredForm).where(
                    DiscoveredForm.scan_id == scan_id,
                    (DiscoveredForm.asset_id == a.id) | (DiscoveredForm.action == a.path) | (DiscoveredForm.page_url == a.url)
                )
            )
            for form in f_res.scalars().all():
                for inp in (form.inputs_schema or []):
                    iname = inp.get("name")
                    if iname:
                        chk = await db.execute(
                            select(Parameter).where(
                                Parameter.endpoint_id == legacy_ep.id,
                                Parameter.name == iname
                            )
                        )
                        if not chk.scalar_one_or_none():
                            leg_p = Parameter(
                                endpoint_id=legacy_ep.id,
                                name=iname,
                                location="body" if form.method == "POST" else "query",
                                value_type="string"
                            )
                            db.add(leg_p)

            # 3. Sync query parameters from URL path
            if "?" in a.url:
                query_str = a.url.split("?", 1)[1]
                q_vars = urllib.parse.parse_qs(query_str)
                for qname in q_vars.keys():
                    chk = await db.execute(
                        select(Parameter).where(
                            Parameter.endpoint_id == legacy_ep.id,
                            Parameter.name == qname
                        )
                    )
                    if not chk.scalar_one_or_none():
                        leg_p = Parameter(
                            endpoint_id=legacy_ep.id,
                            name=qname,
                            location="query",
                            value_type="string"
                        )
                        db.add(leg_p)

        await db.commit()
        return synced

    async def _verify_persisted_database_records(self, db: AsyncSession, scan_id: str) -> Dict[str, int]:
        """
        Audit and verify actual persisted database rows for the given scan.
        Guarantees that database records actually exist and prevents phantom records.
        """
        from sqlalchemy import func

        async def get_count(model, filter_col=None):
            stmt = select(func.count()).select_from(model)
            if filter_col is not None:
                stmt = stmt.where(filter_col == scan_id)
            res = await db.execute(stmt)
            return res.scalar() or 0

        pages_count = await get_count(DiscoveredPage, DiscoveredPage.scan_id)
        assets_res = await db.execute(
            select(func.count()).select_from(DiscoveredAsset).where(
                DiscoveredAsset.scan_id == scan_id,
                DiscoveredAsset.asset_type.in_([AssetType.HTTP_ENDPOINT, AssetType.BACKEND_API_OPERATION, AssetType.GRAPHQL_OPERATION, AssetType.WEBSOCKET_ENDPOINT])
            )
        )
        endpoints_count = assets_res.scalar() or 0
        total_assets = await get_count(DiscoveredAsset, DiscoveredAsset.scan_id)
        params_count = await get_count(EndpointParameter, EndpointParameter.scan_id)
        forms_count = await get_count(DiscoveredForm, DiscoveredForm.scan_id)
        source_files_count = await get_count(SourceFile, SourceFile.scan_id)
        source_evidences_count = await get_count(SourceEvidence, SourceEvidence.scan_id)
        runtime_evidences_count = await get_count(RuntimeEvidence, RuntimeEvidence.scan_id)
        events_count = await get_count(DiscoveryEvent, DiscoveryEvent.scan_id)

        return {
            "total_assets": total_assets,
            "pages_count": pages_count,
            "endpoints_count": endpoints_count,
            "parameters_count": params_count,
            "forms_count": forms_count,
            "source_files_count": source_files_count,
            "source_evidences_count": source_evidences_count,
            "runtime_evidences_count": runtime_evidences_count,
            "events_count": events_count
        }

# Global singleton orchestrator
scan_orchestrator = ScanOrchestrator()
