from enum import Enum
from typing import Optional
from app.scanner.analysis.anomaly import AnomalyReport

class ValidationVerdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"

class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class ConfidenceCalculator:
    @classmethod
    def calculate(
        cls, 
        anomaly: AnomalyReport, 
        validation_reproduced: bool, 
        false_positive_probe_passed: bool
    ) -> tuple[ValidationVerdict, ConfidenceLevel, str]:
        """
        Calculates confidence and final verdict based on validation probes.
        """
        if not validation_reproduced:
            return (
                ValidationVerdict.REJECTED,
                ConfidenceLevel.LOW,
                "Anomaly could not be reproduced during targeted secondary verification"
            )

        if not false_positive_probe_passed:
            return (
                ValidationVerdict.REJECTED,
                ConfidenceLevel.LOW,
                "Targeted control probe demonstrated behavior is identical for benign inputs (false positive)"
            )

        # High confidence for distinct signal indicators
        if anomaly.differential and (anomaly.differential.sql_error_detected or anomaly.differential.payload_reflected):
            return (
                ValidationVerdict.CONFIRMED,
                ConfidenceLevel.HIGH,
                f"Reproducible targeted probe confirmed {anomaly.category} with distinct reflection/error pattern"
            )

        if anomaly.score >= 50:
            return (
                ValidationVerdict.CONFIRMED,
                ConfidenceLevel.MEDIUM,
                f"Reproducible targeted probe confirmed behavioral anomaly (score: {anomaly.score})"
            )

        return (
            ValidationVerdict.INCONCLUSIVE,
            ConfidenceLevel.LOW,
            "Behavioral shift observed but insufficient evidence for definitive confirmation"
        )
