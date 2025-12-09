"""
PDF Report Generator - Professional security assessment reports.
"""
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from io import BytesIO

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, mm
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image, ListFlowable, ListItem, KeepTogether
    )
    from reportlab.graphics.shapes import Drawing, Rect
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    from weasyprint import HTML, CSS
    WEASYPRINT_AVAILABLE = True
except (ImportError, OSError):
    WEASYPRINT_AVAILABLE = False


class PDFReportGenerator:
    """Generate professional PDF security reports"""

    # Color scheme
    COLORS = {
        'primary': colors.HexColor('#1a1a2e'),
        'secondary': colors.HexColor('#16213e'),
        'accent': colors.HexColor('#e94560'),
        'critical': colors.HexColor('#ff0054'),
        'high': colors.HexColor('#ff6b6b'),
        'medium': colors.HexColor('#feca57'),
        'low': colors.HexColor('#48dbfb'),
        'info': colors.HexColor('#1dd1a1'),
        'text': colors.HexColor('#333333'),
        'light_text': colors.HexColor('#666666'),
        'white': colors.white,
        'light_bg': colors.HexColor('#f5f5f5')
    }

    def __init__(self, output_dir: str = './output/reports'):
        """Initialize PDF generator"""
        if not REPORTLAB_AVAILABLE:
            raise ImportError(
                "ReportLab is required for PDF generation. "
                "Install with: pip install reportlab"
            )
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.styles = self._create_styles()

    def _create_styles(self) -> dict:
        """Create custom paragraph styles"""
        base_styles = getSampleStyleSheet()

        custom_styles = {
            'title': ParagraphStyle(
                'CustomTitle',
                parent=base_styles['Heading1'],
                fontSize=28,
                spaceAfter=30,
                textColor=self.COLORS['primary'],
                alignment=TA_CENTER
            ),
            'subtitle': ParagraphStyle(
                'CustomSubtitle',
                parent=base_styles['Normal'],
                fontSize=14,
                spaceAfter=20,
                textColor=self.COLORS['light_text'],
                alignment=TA_CENTER
            ),
            'heading1': ParagraphStyle(
                'CustomH1',
                parent=base_styles['Heading1'],
                fontSize=20,
                spaceBefore=20,
                spaceAfter=15,
                textColor=self.COLORS['primary'],
                borderColor=self.COLORS['accent'],
                borderWidth=2,
                borderPadding=5
            ),
            'heading2': ParagraphStyle(
                'CustomH2',
                parent=base_styles['Heading2'],
                fontSize=16,
                spaceBefore=15,
                spaceAfter=10,
                textColor=self.COLORS['secondary']
            ),
            'heading3': ParagraphStyle(
                'CustomH3',
                parent=base_styles['Heading3'],
                fontSize=13,
                spaceBefore=10,
                spaceAfter=8,
                textColor=self.COLORS['text']
            ),
            'body': ParagraphStyle(
                'CustomBody',
                parent=base_styles['Normal'],
                fontSize=10,
                spaceAfter=8,
                textColor=self.COLORS['text'],
                alignment=TA_JUSTIFY
            ),
            'code': ParagraphStyle(
                'CustomCode',
                parent=base_styles['Code'],
                fontSize=8,
                fontName='Courier',
                backColor=self.COLORS['light_bg'],
                borderColor=colors.lightgrey,
                borderWidth=1,
                borderPadding=5
            ),
            'finding_title': ParagraphStyle(
                'FindingTitle',
                parent=base_styles['Heading3'],
                fontSize=12,
                spaceBefore=5,
                spaceAfter=5,
                textColor=self.COLORS['text']
            ),
            'toc_entry': ParagraphStyle(
                'TOCEntry',
                parent=base_styles['Normal'],
                fontSize=11,
                leftIndent=20,
                spaceAfter=5
            ),
            'executive_summary': ParagraphStyle(
                'ExecutiveSummary',
                parent=base_styles['Normal'],
                fontSize=11,
                spaceAfter=12,
                alignment=TA_JUSTIFY,
                textColor=self.COLORS['text']
            )
        }

        return custom_styles

    def generate(self, report_data: Dict[str, Any], filename: str = None) -> str:
        """Generate PDF report from data"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"security_report_{timestamp}.pdf"

        filepath = os.path.join(self.output_dir, filename)

        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch
        )

        story = []

        # Cover page
        story.extend(self._create_cover_page(report_data))
        story.append(PageBreak())

        # Table of contents
        story.extend(self._create_toc(report_data))
        story.append(PageBreak())

        # Executive summary
        story.extend(self._create_executive_summary(report_data))
        story.append(PageBreak())

        # Findings summary chart
        story.extend(self._create_findings_chart(report_data))
        story.append(Spacer(1, 20))

        # Detailed findings
        story.extend(self._create_findings_section(report_data))
        story.append(PageBreak())

        # Subdomains section (if any)
        if report_data.get('subdomains'):
            story.extend(self._create_subdomains_section(report_data))
            story.append(PageBreak())

        # Endpoints section (if any)
        if report_data.get('endpoints'):
            story.extend(self._create_endpoints_section(report_data))
            story.append(PageBreak())

        # Appendix - methodology
        story.extend(self._create_methodology_section())

        # Build PDF
        doc.build(story, onFirstPage=self._add_header_footer,
                  onLaterPages=self._add_header_footer)

        return filepath

    def _create_cover_page(self, data: Dict) -> List:
        """Create cover page elements"""
        elements = []

        # Add vertical space
        elements.append(Spacer(1, 2 * inch))

        # Title
        elements.append(Paragraph(
            data.get('title', 'Security Assessment Report'),
            self.styles['title']
        ))

        # Subtitle
        target = data.get('target', 'Unknown Target')
        elements.append(Paragraph(
            f"Security Assessment for {target}",
            self.styles['subtitle']
        ))

        elements.append(Spacer(1, inch))

        # Metadata table
        meta_data = [
            ['Target:', target],
            ['Assessment Date:', datetime.now().strftime('%B %d, %Y')],
            ['Prepared By:', data.get('tester', 'AppSec Bounty Platform')],
            ['Classification:', data.get('classification', 'Confidential')]
        ]

        meta_table = Table(meta_data, colWidths=[2 * inch, 4 * inch])
        meta_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('TEXTCOLOR', (0, 0), (-1, -1), self.COLORS['text']),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ]))

        elements.append(meta_table)

        elements.append(Spacer(1, 2 * inch))

        # Risk rating box
        risk_rating = self._calculate_risk_rating(data.get('summary', {}))
        risk_color = self._get_risk_color(risk_rating)

        risk_data = [[f"Overall Risk Rating: {risk_rating.upper()}"]]
        risk_table = Table(risk_data, colWidths=[4 * inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), risk_color),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 16),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
            ('TOPPADDING', (0, 0), (-1, -1), 15),
            ('ROUNDEDCORNERS', [10, 10, 10, 10]),
        ]))

        elements.append(risk_table)

        return elements

    def _create_toc(self, data: Dict) -> List:
        """Create table of contents"""
        elements = []

        elements.append(Paragraph("Table of Contents", self.styles['heading1']))
        elements.append(Spacer(1, 20))

        toc_items = [
            "1. Executive Summary",
            "2. Findings Overview",
            "3. Detailed Findings",
        ]

        if data.get('subdomains'):
            toc_items.append("4. Discovered Subdomains")
        if data.get('endpoints'):
            toc_items.append(f"{len(toc_items) + 1}. Discovered Endpoints")

        toc_items.append(f"{len(toc_items) + 1}. Methodology")

        for item in toc_items:
            elements.append(Paragraph(item, self.styles['toc_entry']))

        return elements

    def _create_executive_summary(self, data: Dict) -> List:
        """Create executive summary section"""
        elements = []

        elements.append(Paragraph("1. Executive Summary", self.styles['heading1']))
        elements.append(Spacer(1, 15))

        summary = data.get('summary', {})

        # Summary text
        summary_text = f"""
        This security assessment was conducted against <b>{data.get('target', 'the target')}</b>
        to identify potential vulnerabilities and security weaknesses. The assessment
        discovered a total of <b>{summary.get('total_findings', 0)}</b> findings across
        various severity levels.
        """
        elements.append(Paragraph(summary_text, self.styles['executive_summary']))

        # Severity breakdown table
        severity_data = summary.get('severity_breakdown', {})
        breakdown_data = [
            ['Severity', 'Count', 'Percentage'],
            ['Critical', str(severity_data.get('critical', 0)), self._calc_percentage(severity_data.get('critical', 0), summary.get('total_findings', 0))],
            ['High', str(severity_data.get('high', 0)), self._calc_percentage(severity_data.get('high', 0), summary.get('total_findings', 0))],
            ['Medium', str(severity_data.get('medium', 0)), self._calc_percentage(severity_data.get('medium', 0), summary.get('total_findings', 0))],
            ['Low', str(severity_data.get('low', 0)), self._calc_percentage(severity_data.get('low', 0), summary.get('total_findings', 0))],
            ['Informational', str(severity_data.get('info', 0)), self._calc_percentage(severity_data.get('info', 0), summary.get('total_findings', 0))],
        ]

        breakdown_table = Table(breakdown_data, colWidths=[2 * inch, 1.5 * inch, 1.5 * inch])
        breakdown_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#ffeeee')),
            ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#fff0f0')),
            ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#fffaee')),
            ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor('#eef8ff')),
            ('BACKGROUND', (0, 5), (-1, 5), colors.HexColor('#eeffee')),
        ]))

        elements.append(breakdown_table)
        elements.append(Spacer(1, 20))

        # Key statistics
        elements.append(Paragraph("Key Statistics", self.styles['heading2']))

        stats_data = [
            ['Metric', 'Value'],
            ['Subdomains Discovered', str(summary.get('total_subdomains', 0))],
            ['Endpoints Discovered', str(summary.get('total_endpoints', 0))],
            ['Risk Score', f"{summary.get('risk_score', 0)}%"],
            ['Scan Duration', summary.get('duration', 'N/A')],
        ]

        stats_table = Table(stats_data, colWidths=[3 * inch, 2 * inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['secondary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.COLORS['light_bg']]),
        ]))

        elements.append(stats_table)

        return elements

    def _create_findings_chart(self, data: Dict) -> List:
        """Create findings pie chart"""
        elements = []

        elements.append(Paragraph("2. Findings Overview", self.styles['heading1']))
        elements.append(Spacer(1, 15))

        summary = data.get('summary', {})
        severity_data = summary.get('severity_breakdown', {})

        # Create pie chart
        drawing = Drawing(400, 200)

        pie = Pie()
        pie.x = 150
        pie.y = 25
        pie.width = 150
        pie.height = 150

        pie_data = [
            severity_data.get('critical', 0),
            severity_data.get('high', 0),
            severity_data.get('medium', 0),
            severity_data.get('low', 0),
            severity_data.get('info', 0)
        ]

        # Only add pie chart if there's data
        if sum(pie_data) > 0:
            pie.data = pie_data
            pie.labels = ['Critical', 'High', 'Medium', 'Low', 'Info']

            pie.slices[0].fillColor = self.COLORS['critical']
            pie.slices[1].fillColor = self.COLORS['high']
            pie.slices[2].fillColor = self.COLORS['medium']
            pie.slices[3].fillColor = self.COLORS['low']
            pie.slices[4].fillColor = self.COLORS['info']

            pie.slices.strokeWidth = 0.5
            pie.slices.strokeColor = colors.white

            drawing.add(pie)
            elements.append(drawing)
        else:
            elements.append(Paragraph(
                "No findings to display in chart.",
                self.styles['body']
            ))

        return elements

    def _create_findings_section(self, data: Dict) -> List:
        """Create detailed findings section"""
        elements = []

        elements.append(Paragraph("3. Detailed Findings", self.styles['heading1']))
        elements.append(Spacer(1, 15))

        findings = data.get('findings', [])

        if not findings:
            elements.append(Paragraph(
                "No security vulnerabilities were identified during this assessment.",
                self.styles['body']
            ))
            return elements

        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(
            findings,
            key=lambda x: severity_order.get(x.get('severity', 'info').lower(), 5)
        )

        for i, finding in enumerate(sorted_findings, 1):
            elements.extend(self._create_finding_entry(finding, i))
            elements.append(Spacer(1, 15))

        return elements

    def _create_finding_entry(self, finding: Dict, index: int) -> List:
        """Create a single finding entry"""
        elements = []

        severity = finding.get('severity', 'info').lower()
        severity_color = self._get_severity_color(severity)

        # Finding header with severity badge
        header_data = [[
            f"#{index}",
            finding.get('title', 'Unknown Finding'),
            severity.upper()
        ]]

        header_table = Table(header_data, colWidths=[0.5 * inch, 4.5 * inch, 1 * inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), self.COLORS['primary']),
            ('TEXTCOLOR', (0, 0), (0, 0), colors.white),
            ('BACKGROUND', (2, 0), (2, 0), severity_color),
            ('TEXTCOLOR', (2, 0), (2, 0), colors.white if severity in ['critical', 'high'] else colors.black),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOX', (0, 0), (-1, -1), 1, colors.grey),
        ]))

        elements.append(header_table)

        # Finding details
        details = []

        if finding.get('tool'):
            details.append(['Tool:', finding['tool']])
        if finding.get('finding_type'):
            details.append(['Type:', finding['finding_type']])
        if finding.get('url'):
            details.append(['URL:', finding['url'][:80] + '...' if len(finding.get('url', '')) > 80 else finding.get('url', '')])
        if finding.get('parameter'):
            details.append(['Parameter:', finding['parameter']])
        if finding.get('cwe_id'):
            details.append(['CWE:', finding['cwe_id']])
        if finding.get('cvss_score'):
            details.append(['CVSS Score:', str(finding['cvss_score'])])

        if details:
            details_table = Table(details, colWidths=[1.2 * inch, 4.8 * inch])
            details_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('TEXTCOLOR', (0, 0), (-1, -1), self.COLORS['text']),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('BACKGROUND', (0, 0), (-1, -1), self.COLORS['light_bg']),
            ]))
            elements.append(details_table)

        # Description
        if finding.get('description'):
            elements.append(Spacer(1, 5))
            elements.append(Paragraph(
                f"<b>Description:</b> {finding['description']}",
                self.styles['body']
            ))

        # Evidence
        if finding.get('evidence'):
            elements.append(Spacer(1, 5))
            elements.append(Paragraph("<b>Evidence:</b>", self.styles['body']))
            elements.append(Paragraph(
                finding['evidence'][:500] + '...' if len(finding.get('evidence', '')) > 500 else finding.get('evidence', ''),
                self.styles['code']
            ))

        # Remediation
        if finding.get('remediation'):
            elements.append(Spacer(1, 5))
            elements.append(Paragraph(
                f"<b>Remediation:</b> {finding['remediation']}",
                self.styles['body']
            ))

        return elements

    def _create_subdomains_section(self, data: Dict) -> List:
        """Create subdomains section"""
        elements = []

        elements.append(Paragraph("4. Discovered Subdomains", self.styles['heading1']))
        elements.append(Spacer(1, 15))

        subdomains = data.get('subdomains', [])[:50]  # Limit to 50

        if not subdomains:
            elements.append(Paragraph("No subdomains discovered.", self.styles['body']))
            return elements

        table_data = [['Subdomain', 'IP Address', 'Status', 'Source']]

        for sub in subdomains:
            table_data.append([
                sub.get('domain', '-')[:40],
                sub.get('ip', sub.get('ip_address', '-')),
                str(sub.get('status_code', '-')),
                sub.get('source', '-')
            ])

        table = Table(table_data, colWidths=[2.5 * inch, 1.2 * inch, 0.8 * inch, 1 * inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.COLORS['light_bg']]),
        ]))

        elements.append(table)

        if len(data.get('subdomains', [])) > 50:
            elements.append(Paragraph(
                f"<i>Showing 50 of {len(data['subdomains'])} subdomains</i>",
                self.styles['body']
            ))

        return elements

    def _create_endpoints_section(self, data: Dict) -> List:
        """Create endpoints section"""
        elements = []

        section_num = 5 if data.get('subdomains') else 4
        elements.append(Paragraph(f"{section_num}. Discovered Endpoints", self.styles['heading1']))
        elements.append(Spacer(1, 15))

        endpoints = data.get('endpoints', [])[:50]  # Limit to 50

        if not endpoints:
            elements.append(Paragraph("No endpoints discovered.", self.styles['body']))
            return elements

        table_data = [['URL', 'Method', 'Status']]

        for ep in endpoints:
            url = ep.get('url', '-')
            table_data.append([
                url[:60] + '...' if len(url) > 60 else url,
                ep.get('method', 'GET'),
                str(ep.get('status_code', '-'))
            ])

        table = Table(table_data, colWidths=[4.5 * inch, 0.8 * inch, 0.7 * inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.COLORS['light_bg']]),
        ]))

        elements.append(table)

        if len(data.get('endpoints', [])) > 50:
            elements.append(Paragraph(
                f"<i>Showing 50 of {len(data['endpoints'])} endpoints</i>",
                self.styles['body']
            ))

        return elements

    def _create_methodology_section(self) -> List:
        """Create methodology appendix"""
        elements = []

        elements.append(Paragraph("Methodology", self.styles['heading1']))
        elements.append(Spacer(1, 15))

        methodology_text = """
        This security assessment followed industry-standard penetration testing
        methodologies including OWASP Testing Guide, PTES (Penetration Testing
        Execution Standard), and OSSTMM (Open Source Security Testing Methodology
        Manual). The assessment was conducted in multiple phases:
        """
        elements.append(Paragraph(methodology_text, self.styles['body']))

        phases = [
            ("Reconnaissance", "Passive and active information gathering including subdomain enumeration, technology fingerprinting, and OSINT."),
            ("Discovery", "Web application crawling, directory brute-forcing, JavaScript analysis, and endpoint discovery."),
            ("Vulnerability Analysis", "Automated scanning with multiple tools followed by manual verification of findings."),
            ("Exploitation Testing", "Controlled exploitation attempts to verify vulnerability impact and severity."),
            ("Reporting", "Compilation of findings with remediation recommendations and risk ratings.")
        ]

        for phase_name, phase_desc in phases:
            elements.append(Paragraph(f"<b>{phase_name}:</b> {phase_desc}", self.styles['body']))

        elements.append(Spacer(1, 20))

        # Severity definitions
        elements.append(Paragraph("Severity Definitions", self.styles['heading2']))

        severity_defs = [
            ("Critical", "Vulnerabilities that can be exploited remotely to execute arbitrary code, gain unauthorized access to sensitive data, or cause significant business impact."),
            ("High", "Vulnerabilities that pose a significant risk but may require specific conditions or user interaction to exploit."),
            ("Medium", "Vulnerabilities that require complex exploitation or have limited impact."),
            ("Low", "Minor vulnerabilities with minimal security impact."),
            ("Informational", "Security best practice recommendations or findings that don't represent immediate risk.")
        ]

        for sev_name, sev_desc in severity_defs:
            elements.append(Paragraph(f"<b>{sev_name}:</b> {sev_desc}", self.styles['body']))

        return elements

    def _add_header_footer(self, canvas, doc):
        """Add header and footer to each page"""
        canvas.saveState()

        # Footer
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(self.COLORS['light_text'])
        canvas.drawString(
            0.75 * inch,
            0.5 * inch,
            "Generated by AppSec Bounty Platform"
        )
        canvas.drawRightString(
            doc.pagesize[0] - 0.75 * inch,
            0.5 * inch,
            f"Page {doc.page}"
        )
        canvas.drawCentredString(
            doc.pagesize[0] / 2,
            0.5 * inch,
            "CONFIDENTIAL"
        )

        canvas.restoreState()

    def _calculate_risk_rating(self, summary: Dict) -> str:
        """Calculate overall risk rating"""
        severity = summary.get('severity_breakdown', {})

        if severity.get('critical', 0) > 0:
            return 'Critical'
        elif severity.get('high', 0) > 0:
            return 'High'
        elif severity.get('medium', 0) > 0:
            return 'Medium'
        elif severity.get('low', 0) > 0:
            return 'Low'
        else:
            return 'Informational'

    def _get_risk_color(self, rating: str) -> colors.Color:
        """Get color for risk rating"""
        color_map = {
            'Critical': self.COLORS['critical'],
            'High': self.COLORS['high'],
            'Medium': self.COLORS['medium'],
            'Low': self.COLORS['low'],
            'Informational': self.COLORS['info']
        }
        return color_map.get(rating, self.COLORS['info'])

    def _get_severity_color(self, severity: str) -> colors.Color:
        """Get color for severity level"""
        return self.COLORS.get(severity.lower(), self.COLORS['info'])

    def _calc_percentage(self, count: int, total: int) -> str:
        """Calculate percentage string"""
        if total == 0:
            return "0%"
        return f"{round((count / total) * 100, 1)}%"


class WeasyPrintPDFGenerator:
    """Alternative PDF generator using WeasyPrint (HTML to PDF)"""

    def __init__(self, output_dir: str = './output/reports'):
        if not WEASYPRINT_AVAILABLE:
            raise ImportError(
                "WeasyPrint is required. Install with: pip install weasyprint"
            )
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_from_html(self, html_content: str, filename: str = None) -> str:
        """Generate PDF from HTML content"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"security_report_{timestamp}.pdf"

        filepath = os.path.join(self.output_dir, filename)

        css = CSS(string='''
            @page {
                margin: 1in;
                @bottom-center {
                    content: "Page " counter(page) " of " counter(pages);
                    font-size: 10px;
                }
            }
            body {
                font-family: Arial, sans-serif;
                font-size: 11pt;
                line-height: 1.6;
            }
        ''')

        HTML(string=html_content).write_pdf(filepath, stylesheets=[css])
        return filepath


if __name__ == "__main__":
    # Example usage
    sample_data = {
        'title': 'Security Assessment Report',
        'target': 'example.com',
        'tester': 'AppSec Bounty Platform',
        'summary': {
            'total_findings': 5,
            'severity_breakdown': {
                'critical': 1,
                'high': 2,
                'medium': 1,
                'low': 1,
                'info': 0
            },
            'total_subdomains': 15,
            'total_endpoints': 42,
            'risk_score': 75
        },
        'findings': [
            {
                'title': 'SQL Injection in Login Form',
                'severity': 'critical',
                'tool': 'sqlmap',
                'finding_type': 'sqli',
                'url': 'https://example.com/login',
                'parameter': 'username',
                'description': 'The login form is vulnerable to SQL injection attacks.',
                'evidence': "Error: You have an error in your SQL syntax near ''",
                'remediation': 'Use parameterized queries or prepared statements.',
                'cwe_id': 'CWE-89',
                'cvss_score': 9.8
            }
        ],
        'subdomains': [
            {'domain': 'api.example.com', 'ip': '192.168.1.1', 'status_code': 200, 'source': 'subfinder'},
            {'domain': 'mail.example.com', 'ip': '192.168.1.2', 'status_code': 200, 'source': 'amass'}
        ],
        'endpoints': [
            {'url': 'https://example.com/api/users', 'method': 'GET', 'status_code': 200},
            {'url': 'https://example.com/api/login', 'method': 'POST', 'status_code': 200}
        ]
    }

    generator = PDFReportGenerator()
    pdf_path = generator.generate(sample_data)
    print(f"PDF report generated: {pdf_path}")
