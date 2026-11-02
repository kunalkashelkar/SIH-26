import asyncio
import logging
import random
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Callable, Awaitable, Tuple
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.discovery import (
    ScanStage, StageAttempt, StageStatus, FailureCategory, DiscoveryError
)
from app.models.models import Scan, ScanLog
from app.core.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

class TransientStageError(Exception):
    """Raised for transient issues like temporary network timeouts or rate limits."""
    pass

class PermanentStageError(Exception):
    """Raised for permanent errors like invalid inputs or unresolvable branches."""
    pass

class EnvironmentalStageError(Exception):
    """Raised for environmental issues like missing browser dependencies or memory limits."""
    pass

class PartialStageError(Exception):
    """Raised when a subtask produces partial output."""
    pass

class RetryPolicy:
    """Configurable retry policy with exponential backoff and jitter."""
    def __init__(
        self,
        max_attempts: int = 3,
        base_delay: float = 0.5,
        max_delay: float = 5.0,
        jitter: bool = True,
        max_retries: Optional[int] = None,
        base_delay_seconds: Optional[float] = None,
        max_delay_seconds: Optional[float] = None
    ):
        self.max_attempts = max_retries if max_retries is not None else max_attempts
        self.base_delay = base_delay_seconds if base_delay_seconds is not None else base_delay
        self.max_delay = max_delay_seconds if max_delay_seconds is not None else max_delay
        self.jitter = jitter

    def compute_delay(self, attempt: int, retry_after: Optional[float] = None) -> float:
        if retry_after is not None and retry_after > 0:
            return min(retry_after, self.max_delay)
        delay = self.base_delay * (2 ** (attempt - 1))
        if self.jitter:
            delay += random.uniform(0, self.base_delay)
        return min(delay, self.max_delay)


def classify_exception(exc: Exception) -> str:
    """
    Classify an exception into FailureCategory:
    TRANSIENT, PERMANENT, ENVIRONMENTAL, PARTIAL, CANCELLED.
    """
    if isinstance(exc, TransientStageError):
        return FailureCategory.TRANSIENT
    if isinstance(exc, PermanentStageError):
        return FailureCategory.PERMANENT
    if isinstance(exc, EnvironmentalStageError):
        return FailureCategory.ENVIRONMENTAL
    if isinstance(exc, PartialStageError):
        return FailureCategory.PARTIAL

    if isinstance(exc, asyncio.CancelledError):
        return FailureCategory.CANCELLED

    exc_str = str(exc).lower()
    exc_type = type(exc).__name__.lower()

    # Cancelled
    if "cancelled" in exc_str or "cancel" in exc_type:
        return FailureCategory.CANCELLED

    # Environmental (Missing Chromium, OS dependencies, out of memory)
    if (
        "playwright" in exc_str and "executable doesn't exist" in exc_str
        or "chromium" in exc_str and "not found" in exc_str
        or "browserType.launch" in exc_str
        or "no usable sandbox" in exc_str
        or "enomem" in exc_str
        or "out of memory" in exc_str
    ):
        return FailureCategory.ENVIRONMENTAL

    # Permanent (Validation errors, 404 Not Found, bad branch, malformed URLs)
    if (
        "not found" in exc_str
        or "404" in exc_str
        or "invalid url" in exc_str
        or "validation" in exc_type
        or "valueerror" in exc_type
        or "bad credentials" in exc_str
        or "401" in exc_str
        or "unauthorized" in exc_str
        or "zip slip" in exc_str
        or "path traversal" in exc_str
    ):
        return FailureCategory.PERMANENT

    # Transient (Timeouts, HTTP 429, Connection resets, DB locks)
    if (
        "timeout" in exc_str
        or "timed out" in exc_str
        or "429" in exc_str
        or "rate limit" in exc_str
        or "connection reset" in exc_str
        or "temporarily unavailable" in exc_str
        or "econnrefused" in exc_str
        or "operationalerror" in exc_type
        or "lock" in exc_str
    ):
        return FailureCategory.TRANSIENT

    # Default to Partial if it's a processing hiccup, or Permanent if unknown
    return FailureCategory.TRANSIENT


class StageExecutionResult:
    def __init__(
        self,
        stage_name: str,
        status: str,
        output_count: int = 0,
        data: Any = None,
        duration: float = 0.0,
        error: Optional[str] = None,
        failure_category: Optional[str] = None,
        retry_count: int = 0
    ):
        self.stage_name = stage_name
        self.status = status
        self.output_count = output_count
        self.data = data
        self.duration = duration
        self.error = error
        self.failure_category = failure_category
        self.retry_count = retry_count

    @property
    def is_success(self) -> bool:
        return self.status in [StageStatus.COMPLETED, StageStatus.PARTIALLY_COMPLETED]


class StageExecutionWrapper:
    """
    Centralized execution wrapper for all pipeline stages.
    Enforces:
    - Prerequisite checking (blocks dependent stages on upstream failure)
    - Retry policies with exponential backoff for transient issues
    - Persistent stage tracking and stage attempt history in DB
    - Accurate execution durations and counters
    - Preservation of previous evidence and assets
    """

    def __init__(self, retry_policy: Optional[RetryPolicy] = None):
        self.retry_policy = retry_policy or RetryPolicy(max_attempts=3, base_delay=0.5, max_delay=3.0)

    async def execute_stage(
        self,
        scan_id: str,
        stage_name: str,
        action: Callable[[], Awaitable[Dict[str, Any]]],
        input_count: int = 0,
        retry_policy: Optional[RetryPolicy] = None,
        prerequisites: Optional[List[str]] = None,
        allow_partial: bool = True,
        db: Optional[AsyncSession] = None
    ) -> Tuple[bool, Any, ScanStage]:
        active_policy = retry_policy or self.retry_policy
        if db:
            result = await self._execute_stage_internal(
                db=db,
                scan_id=scan_id,
                stage_name=stage_name,
                action=action,
                input_count=input_count,
                retry_policy=active_policy,
                prerequisites=prerequisites,
                allow_partial=allow_partial
            )
            rec = await self.get_or_create_stage_record(db, scan_id, stage_name)
            return result.is_success, result.data, rec
        else:
            async with AsyncSessionLocal() as session:
                result = await self._execute_stage_internal(
                    db=session,
                    scan_id=scan_id,
                    stage_name=stage_name,
                    action=action,
                    input_count=input_count,
                    retry_policy=active_policy,
                    prerequisites=prerequisites,
                    allow_partial=allow_partial
                )
                rec = await self.get_or_create_stage_record(session, scan_id, stage_name)
                return result.is_success, result.data, rec

    @staticmethod
    async def get_or_create_stage_record(
        db: AsyncSession,
        scan_id: str,
        stage_name: str,
        input_count: int = 0
    ) -> ScanStage:
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
                stage_status=StageStatus.PENDING,
                input_count=input_count,
                execution_metadata={}
            )
            db.add(stage_rec)
            await db.commit()
            await db.refresh(stage_rec)
        return stage_rec

    @staticmethod
    async def _execute_stage_internal(
        db: AsyncSession,
        scan_id: str,
        stage_name: str,
        action: Callable[[], Awaitable[Dict[str, Any]]],
        input_count: int = 0,
        retry_policy: Optional[RetryPolicy] = None,
        prerequisites: Optional[List[str]] = None,
        allow_partial: bool = True
    ) -> StageExecutionResult:
        if retry_policy is None:
            retry_policy = RetryPolicy(max_attempts=3, base_delay=0.5, max_delay=3.0)

        # 1. Verify Prerequisites
        if prerequisites:
            res_prereqs = await db.execute(
                select(ScanStage).where(
                    ScanStage.scan_id == scan_id,
                    ScanStage.stage_name.in_(prerequisites)
                )
            )
            completed_prereqs = res_prereqs.scalars().all()
            failed_upstream = [
                p.stage_name for p in completed_prereqs
                if p.stage_status in [StageStatus.FAILED, StageStatus.BLOCKED, StageStatus.CANCELLED]
            ]
            if failed_upstream:
                # Mark stage as BLOCKED
                stage_rec = await StageExecutionWrapper.get_or_create_stage_record(db, scan_id, stage_name, input_count)
                stage_rec.stage_status = StageStatus.BLOCKED
                stage_rec.error_message = f"Blocked by failed upstream prerequisite(s): {', '.join(failed_upstream)}"
                stage_rec.failure_category = FailureCategory.PERMANENT
                stage_rec.completed_at = datetime.now(timezone.utc)
                await db.commit()

                logger.warning(f"Stage '{stage_name}' BLOCKED for scan {scan_id} due to upstream failures: {failed_upstream}")
                return StageExecutionResult(
                    stage_name=stage_name,
                    status=StageStatus.BLOCKED,
                    error=stage_rec.error_message,
                    failure_category=FailureCategory.PERMANENT
                )

        stage_rec = await StageExecutionWrapper.get_or_create_stage_record(db, scan_id, stage_name, input_count)
        stage_rec.stage_status = StageStatus.RUNNING
        stage_rec.started_at = datetime.now(timezone.utc)
        stage_rec.input_count = input_count
        await db.commit()

        attempt = 0
        t0 = time.time()
        last_error: Optional[Exception] = None
        failure_cat: Optional[str] = None

        while attempt < retry_policy.max_attempts:
            attempt += 1
            att_t0 = time.time()

            # Record StageAttempt
            attempt_rec = StageAttempt(
                stage_id=stage_rec.id,
                scan_id=scan_id,
                attempt_number=attempt,
                status=StageStatus.RUNNING,
                started_at=datetime.now(timezone.utc)
            )
            db.add(attempt_rec)
            await db.commit()

            try:
                # Execute user action
                output_data = await action()
                duration = round(time.time() - t0, 3)
                att_duration = round(time.time() - att_t0, 3)

                # Successful execution
                output_count = output_data.get("output_count") or output_data.get("discovered", 0) or 1
                status = StageStatus.COMPLETED

                attempt_rec.status = StageStatus.COMPLETED
                attempt_rec.completed_at = datetime.now(timezone.utc)
                attempt_rec.duration = att_duration

                stage_rec.stage_status = status
                stage_rec.completed_at = datetime.now(timezone.utc)
                stage_rec.duration = duration
                stage_rec.processed_count = input_count
                stage_rec.successful_count = output_count
                stage_rec.output_count = output_count
                stage_rec.retry_count = attempt - 1
                stage_rec.execution_metadata = output_data
                await db.commit()

                return StageExecutionResult(
                    stage_name=stage_name,
                    status=status,
                    output_count=output_count,
                    data=output_data,
                    duration=duration,
                    retry_count=attempt - 1
                )

            except Exception as exc:
                last_error = exc
                failure_cat = classify_exception(exc)
                att_duration = round(time.time() - att_t0, 3)

                attempt_rec.status = StageStatus.FAILED
                attempt_rec.error_message = str(exc)
                attempt_rec.failure_category = failure_cat
                attempt_rec.completed_at = datetime.now(timezone.utc)
                attempt_rec.duration = att_duration
                stage_rec.retry_count = attempt
                await db.commit()

                logger.warning(
                    f"Stage '{stage_name}' attempt {attempt}/{retry_policy.max_attempts} failed ({failure_cat}): {exc}"
                )

                if failure_cat in [FailureCategory.PERMANENT, FailureCategory.ENVIRONMENTAL, FailureCategory.CANCELLED]:
                    # Non-retryable
                    break

                if attempt < retry_policy.max_attempts:
                    delay = retry_policy.compute_delay(attempt)
                    logger.info(f"Retrying stage '{stage_name}' in {delay:.2f}s...")
                    await asyncio.sleep(delay)

        # All attempts exhausted or non-retryable failure encountered
        duration = round(time.time() - t0, 3)
        final_status = StageStatus.FAILED
        if allow_partial and failure_cat == FailureCategory.PARTIAL:
            final_status = StageStatus.PARTIALLY_COMPLETED

        stage_rec.stage_status = final_status
        stage_rec.completed_at = datetime.now(timezone.utc)
        stage_rec.duration = duration
        stage_rec.failed_count = 1
        stage_rec.error_code = type(last_error).__name__ if last_error else "UNKNOWN_ERROR"
        stage_rec.error_message = str(last_error) if last_error else "Stage failed"
        stage_rec.failure_category = failure_cat
        await db.commit()

        # Log DiscoveryError record
        db.add(DiscoveryError(
            scan_id=scan_id,
            component=stage_name,
            error_type=type(last_error).__name__ if last_error else "StageFailure",
            message=str(last_error),
            retryable=(failure_cat == FailureCategory.TRANSIENT)
        ))
        await db.commit()

        return StageExecutionResult(
            stage_name=stage_name,
            status=final_status,
            duration=duration,
            error=str(last_error),
            failure_category=failure_cat,
            retry_count=attempt - 1
        )
