import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.models.models import Scan, Target, Endpoint, Parameter, Subdomain, Finding, Evidence, Retest
from app.scanner.analysis.analyzer import SCAN_ANALYSIS_REPORTS

logger = logging.getLogger(__name__)

class ReportBuilder:
    def __init__(self, db: AsyncSession, scan_id: str):
        self.db = db
        self.scan_id = scan_id

    async def build_data(self) -> dict:
        # Load Scan & Target
        scan_res = await self.db.execute(select(Scan).where(Scan.id == self.scan_id))
        scan = scan_res.scalar_one_or_none()
        if not scan:
            raise ValueError(f"Scan {self.scan_id} not found")

        target_res = await self.db.execute(select(Target).where(Target.id == scan.target_id))
        target = target_res.scalar_one_or_none()

        # Load Endpoints & Parameters
        ep_stmt = (
            select(Endpoint)
            .options(selectinload(Endpoint.parameters))
            .where(Endpoint.scan_id == self.scan_id)
        )
        ep_res = await self.db.execute(ep_stmt)
        endpoints = ep_res.scalars().all()

        # Load Subdomains
        sub_res = await self.db.execute(select(Subdomain).where(Subdomain.scan_id == self.scan_id))
        subdomains = sub_res.scalars().all()

        # Load Findings with Evidence and Retests
        f_stmt = (
            select(Finding)
            .options(
                selectinload(Finding.evidence),
                selectinload(Finding.retests),
                selectinload(Finding.endpoint),
                selectinload(Finding.parameter)
            )
            .where(Finding.scan_id == self.scan_id)
            .order_by(Finding.created_at.desc())
        )
        f_res = await self.db.execute(f_stmt)
        findings = f_res.scalars().all()

        # Compute counts
        total_parameters = sum(len(ep.parameters) for ep in endpoints)
        total_apis = sum(1 for ep in endpoints if ep.is_api)
        
        crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")
        med_count = sum(1 for f in findings if f.severity == "MEDIUM")
        low_count = sum(1 for f in findings if f.severity == "LOW")
        verified_fixes = sum(1 for f in findings if f.status in ["VERIFIED_FIXED", "verified_fixed"])

        # Duration
        duration_sec = 0
        if scan.started_at and scan.completed_at:
            duration_sec = int((scan.completed_at - scan.started_at).total_seconds())

        # Anomaly counts from analysis
        analysis_reports = SCAN_ANALYSIS_REPORTS.get(self.scan_id, [])
        anomalies_detected = sum(1 for a in analysis_reports if a.anomaly)
        rejected_anomalies = max(anomalies_detected - len(findings), 0)

        data = {
            "target": {
                "id": target.id if target else None,
                "name": target.name if target else "Unknown",
                "base_url": target.base_url if target else "Unknown"
            },
            "scan": {
                "scan_id": scan.id,
                "status": scan.status,
                "scan_mode": scan.scan_mode or "Standard",
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "duration_seconds": duration_sec,
                "progress": scan.progress
            },
            "attack_surface_summary": {
                "total_endpoints": len(endpoints),
                "total_apis": total_apis,
                "total_parameters": total_parameters,
                "total_subdomains": len(subdomains),
                "subdomains": [s.domain for s in subdomains],
                "endpoints": [
                    {
                        "id": ep.id,
                        "path": ep.path,
                        "method": ep.method,
                        "is_api": ep.is_api,
                        "depth": ep.depth,
                        "priority_score": ep.priority_score,
                        "parameters": [p.name for p in ep.parameters]
                    } for ep in endpoints
                ]
            },
            "risk_summary": {
                "total_findings": len(findings),
                "critical": crit_count,
                "high": high_count,
                "medium": med_count,
                "low": low_count,
                "confirmed": len(findings),
                "verified_fixes": verified_fixes,
                "rejected_anomalies": rejected_anomalies
            },
            "findings": [
                {
                    "id": f.id,
                    "vulnerability_type": f.vulnerability_type,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "priority": f.priority or "P2",
                    "status": f.status,
                    "endpoint_path": f.endpoint.path if f.endpoint else None,
                    "parameter_name": f.parameter.name if f.parameter else None,
                    "cwe": f.cwe,
                    "owasp_category": f.owasp_category,
                    "description": f.description,
                    "impact": f.impact,
                    "remediation": f.remediation,
                    "created_at": f.created_at.isoformat() if f.created_at else None,
                    "evidence": [
                        {
                            "id": ev.id,
                            "evidence_type": ev.evidence_type,
                            "baseline_summary": ev.baseline_summary,
                            "test_summary": ev.test_summary,
                            "analysis": ev.analysis,
                            "confidence": ev.confidence
                        } for ev in f.evidence
                    ],
                    "retests": [
                        {
                            "id": rt.id,
                            "status": rt.status,
                            "result": rt.result,
                            "executed_at": rt.executed_at.isoformat() if rt.executed_at else None
                        } for rt in f.retests
                    ]
                } for f in findings
            ]
        }
        return data
