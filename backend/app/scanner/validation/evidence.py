from typing import Any
from app.scanner.analysis.anomaly import AnomalyReport
from app.scanner.validation.confidence import ConfidenceLevel, ValidationVerdict

class EvidenceItem:
    def __init__(
        self,
        finding_id: str,
        evidence_type: str,
        baseline_summary: str,
        test_summary: str,
        analysis: str,
        confidence: str
    ):
        self.finding_id = finding_id
        self.evidence_type = evidence_type
        self.baseline_summary = baseline_summary
        self.test_summary = test_summary
        self.analysis = analysis
        self.confidence = confidence

class EvidenceCollector:
    @classmethod
    def build_evidence(
        cls,
        finding_id: str,
        anomaly: AnomalyReport,
        verdict: ValidationVerdict,
        confidence: ConfidenceLevel,
        reason: str
    ) -> EvidenceItem:
        analysis_text = f"Verdict: {verdict.value}. Signals: {'; '.join(anomaly.signals)}. {reason}"
        return EvidenceItem(
            finding_id=finding_id,
            evidence_type=f"{anomaly.category}_VALIDATION",
            baseline_summary=anomaly.baseline_summary,
            test_summary=f"{anomaly.test_summary} (Payload: {anomaly.payload})",
            analysis=analysis_text,
            confidence=confidence.value
        )
