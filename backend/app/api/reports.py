from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.models import Scan, Target, Finding
from app.reporting.report_builder import ReportBuilder
from app.reporting.json_report import JSONReportGenerator
from app.reporting.pdf_report import PDFReportGenerator

router = APIRouter()

@router.get("/scans/{scan_id}/json")
async def get_json_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Generate comprehensive JSON security audit report."""
    actual_id = scan_id
    if scan_id == "latest":
        latest = await db.execute(select(Scan).order_by(Scan.started_at.desc().nullslast()).limit(1))
        sc = latest.scalar_one_or_none()
        if not sc:
            raise HTTPException(status_code=404, detail="No scans found")
        actual_id = sc.id

    try:
        report_data = await JSONReportGenerator.generate(db, actual_id)
        return report_data
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.get("/scans/{scan_id}/pdf")
async def get_pdf_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Generate printable PDF security audit report."""
    actual_id = scan_id
    if scan_id == "latest":
        latest = await db.execute(select(Scan).order_by(Scan.started_at.desc().nullslast()).limit(1))
        sc = latest.scalar_one_or_none()
        if not sc:
            raise HTTPException(status_code=404, detail="No scans found")
        actual_id = sc.id

    try:
        pdf_bytes = await PDFReportGenerator.generate_bytes(db, actual_id)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=sentinel_security_report_{actual_id}.pdf"}
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.get("/scans/{scan_id}/sarif")
async def get_sarif_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Generate standard OASIS SARIF v2.1.0 report for CI/CD integrations."""
    actual_id = scan_id
    if scan_id == "latest":
        latest = await db.execute(select(Scan).order_by(Scan.started_at.desc().nullslast()).limit(1))
        sc = latest.scalar_one_or_none()
        if not sc:
            raise HTTPException(status_code=404, detail="No scans found")
        actual_id = sc.id

    builder = ReportBuilder(db, actual_id)
    try:
        data = await builder.build_data()
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    # Construct standard SARIF 2.1.0 schema
    sarif_results = []
    rules = []
    rule_ids = set()

    for finding in data.get("findings", []):
        rule_id = finding.get("cwe") or finding.get("vulnerability_type", "VULN-001")
        if rule_id not in rule_ids:
            rule_ids.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": finding.get("vulnerability_type", "Security Vulnerability"),
                "shortDescription": {"text": finding.get("description", "")[:120]},
                "fullDescription": {"text": finding.get("description", "")},
                "help": {"text": finding.get("remediation", "")},
                "properties": {
                    "tags": ["security", finding.get("owasp_category", "OWASP")],
                    "problem.severity": "error" if finding.get("severity") in ["CRITICAL", "HIGH"] else "warning"
                }
            })

        sarif_results.append({
            "ruleId": rule_id,
            "level": "error" if finding.get("severity") in ["CRITICAL", "HIGH"] else "warning",
            "message": {
                "text": f"{finding.get('vulnerability_type')} detected at {finding.get('endpoint_path', '/')}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.get("endpoint_path", "/")
                        }
                    }
                }
            ],
            "properties": {
                "confidence": finding.get("confidence", "HIGH"),
                "priority": finding.get("priority", "P2"),
                "status": finding.get("status", "open")
            }
        })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sentinel Web Fuzzer",
                        "version": "2.4.0",
                        "informationUri": "https://github.com/sentinel/fuzzer",
                        "rules": rules
                    }
                },
                "results": sarif_results
            }
        ]
    }
    return JSONResponse(
        content=sarif_doc,
        headers={"Content-Disposition": f"attachment; filename=sentinel_sarif_{actual_id}.sarif"}
    )
