"""
Context-Aware Target Selector for Fuzzing Engine.
Evaluates discovery inventory to select safe, authorized, and eligible endpoints for testing.
Prevents blind fuzzing, enforces scope boundaries, and respects state-changing safety policies.
"""
import logging
import urllib.parse
from typing import List, Dict, Any, Optional, Set
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Endpoint, Scan
from app.models.discovery import DiscoveredAsset, DiscoveryStatus, AssetType

logger = logging.getLogger(__name__)

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
STATE_CHANGING_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

class TargetSelector:
    """
    Selects eligible targets for fuzzing based on scope, confirmed runtime observations,
    parameter availability, method safety, and user configuration.
    """

    def __init__(self, db: AsyncSession, scan_id: str, config: Optional[Dict[str, Any]] = None):
        self.db = db
        self.scan_id = scan_id
        self.config = config or {}

        # Configuration options
        self.allow_state_changing = self.config.get("allow_state_changing", True)
        self.allow_source_only = self.config.get("allow_source_only_fuzzing", False)
        self.max_endpoints = self.config.get("max_fuzz_endpoints", 100)

    async def select_eligible_endpoints(self, endpoints: List[Endpoint]) -> List[Endpoint]:
        """
        Filters and ranks endpoints eligible for security testing.
        Stages: DISCOVERED -> ELIGIBLE FOR TESTING
        """
        logger.info(f"[TARGET_SELECTOR] Evaluating {len(endpoints)} discovered endpoints for scan {self.scan_id}")
        eligible: List[Endpoint] = []

        # Load scan record to verify scope
        s_res = await self.db.execute(select(Scan).where(Scan.id == self.scan_id))
        scan = s_res.scalar_one_or_none()
        target_base_url = scan.website_url if scan else None
        target_netloc = urllib.parse.urlparse(target_base_url).netloc if target_base_url else ""

        # Load discovered assets to inspect correlation status
        a_res = await self.db.execute(select(DiscoveredAsset).where(DiscoveredAsset.scan_id == self.scan_id))
        assets_by_url: Dict[str, DiscoveredAsset] = {}
        for a in a_res.scalars().all():
            key = f"{a.method or 'GET'} {a.path}"
            assets_by_url[key] = a

        for ep in endpoints:
            method = (ep.method or "GET").upper()
            ep_key = f"{method} {ep.path}"
            matching_asset = assets_by_url.get(ep_key)

            # 1. Scope Check: must match authorized target domain
            if target_netloc and ep.url:
                ep_netloc = urllib.parse.urlparse(ep.url).netloc
                if ep_netloc and ep_netloc != target_netloc:
                    logger.debug(f"[TARGET_SELECTOR] Skipping out-of-scope endpoint: {ep.url}")
                    continue

            # 2. Source-Only Policy: Do not automatically fuzz unverified source-defined routes
            if matching_asset:
                if matching_asset.discovery_status == DiscoveryStatus.SOURCE_ONLY and not self.allow_source_only:
                    logger.debug(f"[TARGET_SELECTOR] Skipping SOURCE_ONLY endpoint without runtime confirmation: {ep_key}")
                    continue
                if matching_asset.discovery_status == DiscoveryStatus.RESTRICTED and not self.config.get("auth_cookies"):
                    logger.debug(f"[TARGET_SELECTOR] Skipping RESTRICTED endpoint without authorized session: {ep_key}")
                    continue

            # 3. State-Changing Safety Policy
            if method in STATE_CHANGING_METHODS and not self.allow_state_changing:
                logger.debug(f"[TARGET_SELECTOR] Skipping state-changing method {method} under non-destructive policy: {ep_key}")
                continue

            # 4. Target is eligible
            eligible.append(ep)

            # Update lifecycle metadata on matching asset
            if matching_asset:
                if matching_asset.metadata_json is None:
                    matching_asset.metadata_json = {}
                matching_asset.metadata_json["testing_lifecycle"] = "ELIGIBLE_FOR_TESTING"

            if len(eligible) >= self.max_endpoints:
                logger.info(f"[TARGET_SELECTOR] Reached maximum eligible endpoint budget ({self.max_endpoints})")
                break

        await self.db.commit()
        logger.info(f"[TARGET_SELECTOR] Selected {len(eligible)} / {len(endpoints)} endpoints as eligible for fuzzing.")
        return eligible
