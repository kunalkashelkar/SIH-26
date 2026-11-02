import asyncio
import logging
from app.workers.celery_app import celery_app
from app.scanner.orchestrator import scan_orchestrator

logger = logging.getLogger(__name__)

if celery_app is not None:
    @celery_app.task(bind=True, name="app.workers.tasks.run_scan_task", max_retries=2)
    def run_scan_task(self, scan_id: str, configuration: dict = None):
        """
        Celery background worker task for running end-to-end scans.
        Wraps asynchronous orchestrator lifecycle execution inside synchronous worker thread.
        """
        logger.info(f"[WORKER] Starting background Celery scan task for scan {scan_id}")
        cancel_event = asyncio.Event()

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(
                    scan_orchestrator._run_orchestrated_lifecycle(
                        scan_id=scan_id,
                        config=configuration or {},
                        cancel_event=cancel_event
                    )
                )
                logger.info(f"[WORKER] Completed Celery scan task for scan {scan_id}")
                return {"scan_id": scan_id, "status": "COMPLETED"}
            finally:
                loop.close()
        except Exception as exc:
            logger.error(f"[WORKER] Scan task failed for {scan_id}: {exc}", exc_info=True)
            err_str = str(exc).lower()
            if "connection" in err_str or "timeout" in err_str:
                raise self.retry(exc=exc, countdown=15)
            raise exc
else:
    def run_scan_task(scan_id: str, configuration: dict = None):
        logger.debug(f"Celery not installed; run_scan_task stub called for {scan_id}")
