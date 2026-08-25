import asyncio
import logging
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.models.models import Finding, Evidence, Endpoint, Parameter
from app.scanner.http_client import ResilientHttpClient
from app.scanner.analysis.anomaly import AnomalyReport
from app.scanner.validation.confidence import ConfidenceCalculator, ValidationVerdict, ConfidenceLevel
from app.scanner.validation.evidence import EvidenceCollector

logger = logging.getLogger(__name__)

class EvidenceValidator:
    def __init__(self, db: AsyncSession, scan_id: str, client: ResilientHttpClient):
        self.db = db
        self.scan_id = scan_id
        self.client = client

    async def validate_anomalies(self, anomalies: list[AnomalyReport], cancel_event: asyncio.Event) -> list[Finding]:
        logger.info(f"Starting Evidence Validation on {len(anomalies)} anomalies for scan {self.scan_id}")
        confirmed_findings: list[Finding] = []

        # Filter only genuine anomalies
        suspicious_list = [a for a in anomalies if a.anomaly]

        for anomaly in suspicious_list:
            if cancel_event.is_set():
                break

            # 1. Fetch endpoint info
            ep_res = await self.db.execute(select(Endpoint).where(Endpoint.id == anomaly.endpoint_id))
            endpoint = ep_res.scalar_one_or_none()
            if not endpoint:
                continue

            # 2. Targeted validation request (reproducibility probe)
            reproduced = False
            try:
                params = {anomaly.parameter_name: anomaly.payload} if (endpoint.method or "GET").upper() == "GET" else None
                data = {anomaly.parameter_name: anomaly.payload} if (endpoint.method or "GET").upper() == "POST" else None
                
                v_resp = await self.client._request(
                    method=endpoint.method or "GET",
                    url=endpoint.url,
                    params=params,
                    data=data
                )
                if v_resp and v_resp.status_code in [200, 500]:
                    v_body = v_resp.text if hasattr(v_resp, "text") else ""
                    # Check if error or reflection reproduces
                    if anomaly.category == "XSS" and anomaly.payload in v_body:
                        reproduced = True
                    elif "syntax error" in v_body.lower() or "sqlite3" in v_body.lower():
                        reproduced = True
                    elif v_resp.status_code == 500:
                        reproduced = True
            except Exception as e:
                logger.warning(f"Validation probe failed for {endpoint.url}: {e}")

            # 3. Control probe (benign input check)
            control_passed = True
            try:
                c_params = {anomaly.parameter_name: "safe123"} if (endpoint.method or "GET").upper() == "GET" else None
                c_data = {anomaly.parameter_name: "safe123"} if (endpoint.method or "GET").upper() == "POST" else None
                c_resp = await self.client._request(
                    method=endpoint.method or "GET",
                    url=endpoint.url,
                    params=c_params,
                    data=c_data
                )
                if c_resp and c_resp.status_code == 500:
                    # If benign input also causes 500, then 500 is not caused by vulnerability
                    control_passed = False
            except Exception:
                pass

            # 4. Compute Confidence and Verdict
            verdict, confidence, reason = ConfidenceCalculator.calculate(
                anomaly=anomaly,
                validation_reproduced=reproduced,
                false_positive_probe_passed=control_passed
            )

            logger.info(f"Validation for {anomaly.parameter_name} ({anomaly.category}): {verdict.value} (Confidence: {confidence.value})")

            # 5. Persist CONFIRMED findings to PostgreSQL / SQLite
            if verdict == ValidationVerdict.CONFIRMED:
                finding_id = str(uuid.uuid4())
                
                # Metadata mappings
                owasp_map = {
                    "SQLI": "A03:2021-Injection",
                    "XSS": "A03:2021-Injection",
                    "IDOR": "A01:2021-Broken Access Control",
                    "AUTH_BYPASS": "A07:2021-Identification and Authentication Failures",
                    "OPEN_REDIRECT": "A01:2021-Broken Access Control"
                }
                cwe_map = {
                    "SQLI": "CWE-89",
                    "XSS": "CWE-79",
                    "IDOR": "CWE-639",
                    "AUTH_BYPASS": "CWE-287",
                    "OPEN_REDIRECT": "CWE-601"
                }
                severity_map = {
                    "SQLI": "HIGH",
                    "XSS": "MEDIUM",
                    "IDOR": "HIGH",
                    "AUTH_BYPASS": "CRITICAL",
                    "OPEN_REDIRECT": "LOW"
                }

                finding = Finding(
                    id=finding_id,
                    scan_id=self.scan_id,
                    endpoint_id=endpoint.id,
                    parameter_id=anomaly.parameter_id,
                    vulnerability_type=f"{anomaly.category} Vulnerability",
                    severity=severity_map.get(anomaly.category, "MEDIUM"),
                    confidence=confidence.value,
                    status="open",
                    description=f"Confirmed {anomaly.category} behavior on parameter '{anomaly.parameter_name}' at {endpoint.path}.",
                    impact=f"Attacker could exploit this {anomaly.category} behavior to manipulate application data or context.",
                    cwe=cwe_map.get(anomaly.category, "CWE-20"),
                    owasp_category=owasp_map.get(anomaly.category, "A03:2021-Injection"),
                    remediation=f"Sanitize and validate user input on parameter '{anomaly.parameter_name}', use parameterized queries or output encoding."
                )
                self.db.add(finding)

                evidence_item = EvidenceCollector.build_evidence(
                    finding_id=finding_id,
                    anomaly=anomaly,
                    verdict=verdict,
                    confidence=confidence,
                    reason=reason
                )

                evidence = Evidence(
                    id=str(uuid.uuid4()),
                    finding_id=finding_id,
                    evidence_type=evidence_item.evidence_type,
                    baseline_summary=evidence_item.baseline_summary,
                    test_summary=evidence_item.test_summary,
                    analysis=evidence_item.analysis,
                    confidence=evidence_item.confidence
                )
                self.db.add(evidence)
                confirmed_findings.append(finding)

        await self.db.commit()
        logger.info(f"Validation stage completed. Stored {len(confirmed_findings)} confirmed findings.")
        return confirmed_findings
