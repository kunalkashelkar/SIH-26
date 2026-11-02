"""
Asset Classification and Explainable Confidence Scoring Model.
Classifies correlated assets and provides explainable, reproducible confidence ratings.
"""
import logging
from typing import Dict, Any, Optional, Tuple

from app.models.discovery import DiscoveryStatus

logger = logging.getLogger(__name__)

class ConfidenceLevel:
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class AssetClassifier:
    """
    Classifies discovered assets and assigns deterministic, explainable confidence scores.
    """

    @classmethod
    def classify_asset(
        cls,
        has_source: bool,
        has_runtime: bool,
        has_spec: bool = False,
        is_candidate: bool = False,
        response_status: Optional[int] = None
    ) -> Tuple[str, str, float, str]:
        """
        Determines the canonical status, confidence level, numeric score, and explanation.
        Returns:
            (classification_status, confidence_level, score, explanation)
        """
        # 1. Restricted (Observed at runtime but access denied)
        if has_runtime and response_status in [401, 403]:
            return (
                DiscoveryStatus.RESTRICTED,
                ConfidenceLevel.HIGH,
                0.95,
                f"Observed at runtime but inaccessible in the current session (HTTP {response_status})."
            )

        # 2. Source and Runtime Match
        if has_source and has_runtime:
            return (
                DiscoveryStatus.SOURCE_AND_RUNTIME_MATCH,
                ConfidenceLevel.HIGH,
                1.00,
                "Directly observed at runtime and confirmed by source code definition."
            )

        # 3. Source Only
        if has_source and not has_runtime:
            return (
                DiscoveryStatus.SOURCE_ONLY,
                ConfidenceLevel.MEDIUM,
                0.85,
                "Declared in source code repository but not observed during runtime crawling (e.g., unlinked, admin, or background route)."
            )

        # 4. Specification Only
        if has_spec and not has_runtime and not has_source:
            return (
                DiscoveryStatus.SPECIFICATION_ONLY,
                ConfidenceLevel.MEDIUM,
                0.80,
                "Documented in OpenAPI / Swagger specification but not verified in source code or observed at runtime."
            )

        # 5. Runtime Only
        if has_runtime and not has_source:
            return (
                DiscoveryStatus.RUNTIME_ONLY,
                ConfidenceLevel.HIGH,
                0.90,
                "Observed in runtime HTTP / browser network traffic but has no corresponding route definition in analyzed source repository."
            )

        # 6. Candidate
        if is_candidate:
            return (
                DiscoveryStatus.CANDIDATE,
                ConfidenceLevel.LOW,
                0.55,
                "Extracted as a candidate URL pattern from static bundle strings or heuristic regex."
            )

        # 7. Unresolved
        return (
            DiscoveryStatus.UNRESOLVED,
            ConfidenceLevel.LOW,
            0.40,
            "Insufficient evidence to establish a definitive asset correlation."
        )
