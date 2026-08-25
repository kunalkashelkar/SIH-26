import html
import io
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from app.reporting.report_builder import ReportBuilder

logger = logging.getLogger(__name__)

class PDFReportGenerator:
    @classmethod
    async def generate_bytes(cls, db: AsyncSession, scan_id: str) -> bytes:
        builder = ReportBuilder(db, scan_id)
        data = await builder.build_data()

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Heading1'],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#1e293b"),
            spaceAfter=8
        )
        heading_style = ParagraphStyle(
            'SectionHeading',
            parent=styles['Heading2'],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=14,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'DocBody',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#334155")
        )
        meta_style = ParagraphStyle(
            'MetaStyle',
            parent=styles['Normal'],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#64748b")
        )

        story = []

        # 1. Header & Title
        story.append(Paragraph("Security Assessment Report", title_style))
        story.append(Paragraph(f"Target: <b>{html.escape(data['target']['base_url'] or '')}</b> | Scan ID: {data['scan']['scan_id']}", meta_style))
        story.append(Spacer(1, 14))

        # 2. Executive Summary
        story.append(Paragraph("1. Executive Summary", heading_style))
        exec_text = (
            f"An automated vulnerability assessment and attack surface discovery was completed for <b>{html.escape(data['target']['base_url'] or '')}</b>. "
            f"During the scan, a total of <b>{data['attack_surface_summary']['total_endpoints']}</b> endpoints and "
            f"<b>{data['attack_surface_summary']['total_parameters']}</b> input parameters were analyzed. "
            f"The scanner identified <b>{data['risk_summary']['total_findings']}</b> confirmed vulnerabilities requiring developer remediation."
        )
        story.append(Paragraph(exec_text, body_style))
        story.append(Spacer(1, 10))

        # 3. Risk Summary Table
        risk = data["risk_summary"]
        risk_table_data = [
            ["Severity Level", "Confirmed Findings", "Status"],
            ["CRITICAL", str(risk["critical"]), "Immediate Attention Required" if risk["critical"] > 0 else "None"],
            ["HIGH", str(risk["high"]), "High Priority Fix" if risk["high"] > 0 else "None"],
            ["MEDIUM", str(risk["medium"]), "Remediate in Sprint" if risk["medium"] > 0 else "None"],
            ["LOW", str(risk["low"]), "Review when possible" if risk["low"] > 0 else "None"],
        ]
        t = Table(risk_table_data, colWidths=[120, 140, 260])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        story.append(t)
        story.append(Spacer(1, 14))

        # 4. Attack Surface Summary
        story.append(Paragraph("2. Attack Surface Summary", heading_style))
        surf = data["attack_surface_summary"]
        surf_text = (
            f"Discovered {surf['total_endpoints']} total endpoints ({surf['total_apis']} REST APIs) "
            f"across {surf['total_subdomains']} subdomains with {surf['total_parameters']} testable parameters."
        )
        story.append(Paragraph(surf_text, body_style))
        story.append(Spacer(1, 14))

        # 5. Detailed Findings & Evidence
        story.append(Paragraph("3. Confirmed Vulnerabilities & Remediation", heading_style))
        if not data["findings"]:
            story.append(Paragraph("No vulnerabilities were identified during this assessment.", body_style))
        else:
            for idx, f in enumerate(data["findings"], 1):
                story.append(Paragraph(f"<b>{idx}. {html.escape(f['vulnerability_type'] or '')}</b> ({f['severity']} - Priority {f['priority']})", heading_style))
                story.append(Paragraph(f"<b>Endpoint:</b> {html.escape(f['endpoint_path'] or '/')} | <b>CWE:</b> {html.escape(f['cwe'] or '')} | <b>OWASP:</b> {html.escape(f['owasp_category'] or '')}", meta_style))
                story.append(Spacer(1, 4))
                story.append(Paragraph(f"<b>Description:</b> {html.escape(f['description'] or '')}", body_style))
                story.append(Paragraph(f"<b>Impact:</b> {html.escape(f['impact'] or '')}", body_style))
                story.append(Spacer(1, 4))
                
                # Evidence
                if f["evidence"]:
                    ev = f["evidence"][0]
                    story.append(Paragraph(f"<b>Verified Evidence:</b> {html.escape(ev['analysis'] or '')}", meta_style))
                    if ev["test_summary"]:
                        story.append(Paragraph(f"<b>Probe:</b> {html.escape(ev['test_summary'] or '')}", meta_style))

                # Remediation
                story.append(Spacer(1, 4))
                rem_formatted = html.escape(f['remediation'] or '').replace('\n', '<br/>')
                story.append(Paragraph(f"<b>Remediation Guidance:</b><br/>{rem_formatted}", body_style))

                # Retest results
                if f["retests"]:
                    last_rt = f["retests"][0]
                    story.append(Paragraph(f"<b>Latest Retest Status:</b> {html.escape(last_rt['result'] or '')} (Status: {f['status']})", meta_style))

                story.append(Spacer(1, 12))

        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
