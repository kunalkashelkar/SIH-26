import asyncio
import logging
from datetime import datetime
from sqlalchemy.future import select

from app.core.database import AsyncSessionLocal
from app.models.models import Scan

logger = logging.getLogger(__name__)

class ScanCancelledError(Exception):
    pass

STAGES = [
    ("INITIALIZING", 5),
    ("DISCOVERY", 20),
    ("ATTACK_SURFACE", 35),
    ("PRIORITIZATION", 40),
    ("FUZZING", 75),
    ("ANALYSIS", 90),
    ("VALIDATION", 95),
    ("REPORTING", 100),
]

async def check_cancellation(cancel_event: asyncio.Event):
    if cancel_event.is_set():
        raise ScanCancelledError("Scan was cancelled by user.")

async def update_scan_state(db, scan_id: str, status: str, current_stage: str, progress: int, error_message: str = None):
    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = res.scalar_one_or_none()
    if scan:
        scan.status = status
        scan.current_stage = current_stage
        scan.progress = progress
        if error_message:
            scan.error_message = error_message
        if status in ["COMPLETED", "CANCELLED", "FAILED"]:
            scan.completed_at = datetime.utcnow()
        await db.commit()

async def run_scan_lifecycle(scan_id: str, scan_req: dict, cancel_event: asyncio.Event):
    """
    Main background task to execute the scan lifecycle.
    """
    logger.info(f"Scan {scan_id} execution started.")
    
    # We create a local session for this background task
    async with AsyncSessionLocal() as db:
        try:
            await update_scan_state(db, scan_id, "RUNNING", "INITIALIZING", 0)
            
            for stage_name, target_progress in STAGES:
                await check_cancellation(cancel_event)
                
                logger.info(f"Scan {scan_id} entering stage {stage_name}")
                await update_scan_state(db, scan_id, "RUNNING", stage_name, target_progress)
                
                if stage_name == "DISCOVERY":
                    # Use the Discovery Engine
                    from app.scanner.discovery.crawler import AsyncCrawler
                    from app.scanner.http_client import ResilientHttpClient
                    from app.scanner.discovery.directory_discovery import DirectoryDiscoverer
                    from app.scanner.discovery.subdomain_discovery import SubdomainDiscoverer
                    
                    max_reqs = scan_req.get("max_requests", 1000)
                    max_depth = scan_req.get("max_depth", 3)
                    enable_sub = scan_req.get("enable_subdomain_discovery", False)
                    enable_dir = scan_req.get("enable_directory_discovery", False)
                    wordlist_limit = scan_req.get("wordlist_limit", 100)
                    target_url = scan_req["target_url"]
                    
                    # Create a resilient client for the crawler
                    client = ResilientHttpClient(max_requests=max_reqs, concurrency=10, timeout=10)
                    try:
                        # 1. Subdomain Discovery (Optional)
                        if enable_sub:
                            sub_discoverer = SubdomainDiscoverer(scan_id, target_url, db, wordlist_limit=wordlist_limit)
                            await sub_discoverer.run(cancel_event)
                            
                        # 2. Directory Discovery (Optional)
                        if enable_dir:
                            dir_discoverer = DirectoryDiscoverer(scan_id, target_url, db, client, wordlist_limit=wordlist_limit)
                            await dir_discoverer.run(cancel_event)
                            
                        # 3. Web Crawler
                        crawler = AsyncCrawler(scan_id, target_url, db, client, max_depth=max_depth)
                        await crawler.run(cancel_event)
                    finally:
                        await client.close()
                elif stage_name == "ATTACK_SURFACE":
                    from app.scanner.analyzer import AttackSurfaceAnalyzer
                    analyzer = AttackSurfaceAnalyzer(db, scan_id)
                    await analyzer.analyze()
                else:
                    # Mock work for other stages
                    for _ in range(5):
                        await asyncio.sleep(1) # simulate work
                        await check_cancellation(cancel_event)

             # Final success state
            await update_scan_state(db, scan_id, "COMPLETED", "COMPLETED", 100)
            logger.info(f"Scan {scan_id} completed successfully.")
            
        except ScanCancelledError as e:
            logger.warning(f"Scan {scan_id} cancelled: {e}")
            await update_scan_state(db, scan_id, "CANCELLED", "CANCELLED", 0, str(e))
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
            await update_scan_state(db, scan_id, "FAILED", "FAILED", 0, str(e))
