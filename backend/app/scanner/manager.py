import asyncio
import logging
from typing import Dict

from app.scanner.executor import run_scan_lifecycle

logger = logging.getLogger(__name__)

class ScanManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ScanManager, cls).__new__(cls)
            cls._instance.active_tasks = {}
            cls._instance.cancellation_events = {}
        return cls._instance

    def start_scan(self, scan_id: str, scan_req: dict):
        if scan_id in self.active_tasks:
            logger.warning(f"Scan {scan_id} is already running.")
            return

        cancel_event = asyncio.Event()
        self.cancellation_events[scan_id] = cancel_event

        # Spawn the background task
        task = asyncio.create_task(run_scan_lifecycle(scan_id, scan_req, cancel_event))
        self.active_tasks[scan_id] = task
        
        # Add cleanup callback
        task.add_done_callback(lambda t: self._cleanup_scan(scan_id))
        logger.info(f"Started background scan task for {scan_id}")

    def cancel_scan(self, scan_id: str) -> bool:
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
        logger.info(f"Cleaned up tasks for scan {scan_id}")

scan_manager = ScanManager()
