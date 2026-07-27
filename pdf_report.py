# TrinTech Digital Defense — Professional PDF Report Generator
# Generates client-ready, non-technical security audit reports
# Enhanced with: CVE details, donut chart, remediation guide

import os
import re
from datetime import datetime
from pathlib import Path

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, mm
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, KeepTogether, HRFlowable, Flowable
    )
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

# TrinTech branding colors
TRINTECH_NAVY = colors.Color(0x0a, 0x16, 0x28)
TRINTECH_BLUE = colors.Color(0x16, 0x86, 0xff)
TRINTECH_CYAN = colors.Color(0x06, 0xb6, 0xd4)
TRINTECH_GREEN = colors.Color(0x10, 0xb9, 0x81)
TRINTECH_YELLOW = colors.Color(0xea, 0xb3, 0x08)
TRINTECH_ORANGE = colors.Color(0xf9, 0x73, 0x16)
TRINTECH_RED = colors.Color(0xef, 0x44, 0x44)
TRINTECH_WHITE = colors.Color(0xff, 0xff, 0xff)
TRINTECH_GRAY = colors.Color(0x6b, 0x72, 0x80)
TRINTECH_LIGHT_GRAY = colors.Color(0xf3, 0xf4, 0xf6)
TRINTECH_BORDER = colors.Color(0x1e, 0x2d, 0x40)

BRAND = {
    "name": "TrinTech Digital Defense",
    "tagline": "DEFEND. DETECT. DOMINATE.",
    "email": "trintechdigitaldefense@gmail.com",
    "phone": "+1 (868) 362-0679",
    "location": "Trinidad & Tobago 🇹🇹",
    "website": "trintechdigitaldefense.github.io",
}


class DonutChart(Flowable):
    """Render a donut chart for the security score."""

    def __init__(self, diameter, score_val):
        Flowable.__init__(self)
        self.diameter = diameter
        self.score_val = score_val
        self.width = diameter
        self.height = diameter

    def draw(self):
        self.canv.saveState()
        # Outer background ring
        self.canv.setFillColor(score_color(self.score_val))
        self.canv.circle(self.width / 2, self.height / 2, self.diameter / 2, fill=1, stroke=0)

        # Inner ring (the "fill" — score percentage)
        import math
        angle = 360 * (self.score_val / 100) - 90
        self.canv.setFillColor(TRINTECH_NAVY)
        self.canv.arc(self.width / 2, self.height / 2, self.diameter / 2, self.diameter / 2, 0, angle)

        # White center
        inner_r = self.diameter * 0.6 / 2
        self.canv.setFillColor(TRINTECH_WHITE)
        self.canv.circle(self.width / 2, self.height / 2, inner_r, fill=1, stroke=0)

        # Score number
        self.canv.setFillColor(TRINTECH_NAVY)
        self.canv.setFont('Helvetica-Bold', 30)
        self.canv.drawCentredString(self.width / 2, self.height / 2 + 10, str(self.score_val))

        # "out of 100"
        self.canv.setFont('Helvetica', 9)
        self.canv.setFillColor(TRINTECH_GRAY)
        self.canv.drawCentredString(self.width / 2, self.height / 2 - 14, "out of 100")

        self.canv.restoreState()


def generate_report(engagement, scan_data):
    """Generate a professional PDF report from scan data."""
    if not HAS_REPORTLAB:
        print("  Error: reportlab not installed. Run: pip install reportlab")
        return None

    eng = engagement
    client_name = eng.get("client_name", "Client")
    target = eng.get("target", "N/A")
    service = eng.get("service", "micro")
    eng_id = eng.get("id", "N/A")
    created = eng.get("created", "")

    # Extract data from all modules
    recon_data = scan_data.get("recon", {})
    web_data = scan_data.get("web", {})
    osint_data = scan_data.get("osint", {})
    vuln_data = scan_data.get("vuln", {})

    # Compile all findings
    all_findings = _compile_all_findings(vuln_data, web_data)

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "INFO"), 9))

    summary = vuln_data.get("summary", {})
    score = calculate_security_score(summary)

    # Generate PDF
    output_dir = Path(__file__).parent / "reports"
    output_dir.mkdir(exist_ok=True)
    filename = f"{eng_id}_{client_name.replace(' ', '_')[:20]}_Audit_Report.pdf"
    filepath = output_dir / filename

    doc = SimpleDocTemplate(
        str(filepath),
        pagesize=letter,
        topMargin=0.5 * inch,
        bottomMargin=0.5 * inch,
        leftMargin=0.7 * inch,
        rightMargin=0.7 * inch,
    )

    styles = getSampleStyleSheet()
    elements = []

    # Build the report
    _build_cover_page(elements, client_name, target, eng_id, created, service, score)
    elements.append(Spacer(1, 24))
    _build_executive_summary(elements, client_name, target, eng_id, score, summary, all_findings)
    elements.append(Spacer(1, 12))
    _build_findings_section(elements, all_findings)
    elements.append(Spacer(1, 12))
    _build_recon_findings(elements, recon_data)
    elements.append(Spacer(1, 12))
    _build_remediation_roadmap(elements, all_findings)
    elements.append(Spacer(1, 12))
    _build_conclusion(elements, client_name, eng_id)
    _build_footer_elements(elements)

    # Separate remediation guide (additional appendix)
    elements.append(PageBreak())
    _build_remediation_guide(elements, all_findings)

    build_result = doc.build(elements)
    return filename


def _compile_all_findings(vuln_data, web_data):
    """Merge all findings from all modules."""
    all_findings = []

    # From vuln scan
    vuln_findings = vuln_data.get("findings", [])

    # From web scan
    web_findings = []
    if isinstance(web_data, dict):
        for ep in web_data.get("endpoints", []):
            for f in ep.get("security_findings", []):
                f["url"] = ep.get("url", "")
            for mh in ep.get("missing_headers", []):
                if isinstance(mh, dict):
                    web_findings.append({
                        "severity": mh.get("severity", "LOW"),
                        "title": f"Missing Security Header: {mh.get('header', '')}",
                        "description": mh.get("risk", ""),
                        "remediation": mh.get("fix", ""),
                    })
            for ci in ep.get("cookie_issues", []):
                web_findings.append({
                    "severity": ci.get("severity", "MEDIUM"),
                    "title": f"Insecure Cookie: {ci.get('name', 'unknown')}",
                    "description": ci.get("detail", ""),
                    "remediation": ci.get("remediation", ""),
                    "url": ep.get("url", ""),
                })
            for cci in ep.get("cors_issues", []):
                web_findings.append({
                    "severity": cci.get("severity", "MEDIUM"),
                    "title": cci.get("title", "CORS Misconfiguration"),
                    "description": cci.get("detail", ""),
                    "remediation": cci.get("remediation", ""),
                    "url": ep.get("url", ""),
                })
        if "security_findings" in web_data:
            web_findings.extend(web_data["security_findings"])

    # Merge all (deduplicate by title + port)
    seen_keys = set()
    for f in vuln_findings:
        key = (f["title"], f.get("port", ""))
        if key not in seen_keys:
            all_findings.append(f)
            seen_keys.add(key)
    for f in web_findings:
        if f.get("title") and f["title"] not in seen_keys:
            all_findings.append(f)
            seen_keys.add(f["title"])

    return all_findings


def calculate_security_score(summary):
    """Calculate an overall security score (0-100)."""
    score = 100
    score -= summary.get("critical", 0) * 25
    score -= summary.get("high", 0) * 12
    score -= summary.get("medium", 0) * 5
    score -= summary.get("low", 0) * 2
    return max(0, min(100, score))


def score_color(score):
    if score >= 80:
        return TRINTECH_GREEN
    elif score >= 60:
        return TRINTECH_YELLOW
    elif score >= 40:
        return TRINTECH_ORANGE
    else:
        return TRINTECH_RED


def score_grade(score):
    if score >= 90:
        return "A - Excellent"
    elif score >= 80:
        return "B - Good"
    elif score >= 70:
        return "C - Fair"
    elif score >= 60:
        return "D - Poor"
    else:
        return "F - Critical"


# ============== PAGE BUILDERS ==============

def _build_cover_page(elements, client_name, target, eng_id, created, service, score):
    """Build the cover page with donut chart."""
    title_style = ParagraphStyle('CoverTitle', fontName='Helvetica-Bold',
                                  fontSize=28, textColor=TRINTECH_BLUE, spaceAfter=12, alignment=TA_LEFT)
    elements.append(Paragraph("SECURITY AUDIT REPORT", title_style))

    subtitle_style = ParagraphStyle('CoverSub', fontName='Helvetica',
                                     fontSize=16, textColor=TRINTECH_CYAN, spaceAfter=24)
    elements.append(Paragraph("Network & Infrastructure Assessment", subtitle_style))

    elements.append(HRFlowable(width="100%", thickness=2, color=TRINTECH_BLUE))
    elements.append(Spacer(1, 20))

    # Client info table
    client_info = [
        [Paragraph(f"<b>Client:</b>", ParagraphStyle('Label', fontName='Helvetica', fontSize=11)),
         Paragraph(client_name, ParagraphStyle('Value', fontName='Helvetica', fontSize=11))],
        [Paragraph(f"<b>Target:</b>", ParagraphStyle('Label2', fontName='Helvetica', fontSize=11)),
         Paragraph(target, ParagraphStyle('Value2', fontName='Helvetica', fontSize=11))],
        [Paragraph(f"<b>Report ID:</b>", ParagraphStyle('Label3', fontName='Helvetica', fontSize=11)),
         Paragraph(eng_id, ParagraphStyle('Value3', fontName='Helvetica', fontSize=11))],
        [Paragraph(f"<b>Date:</b>", ParagraphStyle('Label4', fontName='Helvetica', fontSize=11)),
         Paragraph(created[:10] if created else datetime.now().strftime("%Y-%m-%d"),
                   ParagraphStyle('Value4', fontName='Helvetica', fontSize=11))],
        [Paragraph(f"<b>Service:</b>", ParagraphStyle('Label5', fontName='Helvetica', fontSize=11)),
         Paragraph(service.title(), ParagraphStyle('Value5', fontName='Helvetica', fontSize=11))],
    ]

    info_table = Table(client_info, colWidths=[2.5 * inch, 4.5 * inch])
    info_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('FONTSIZE', (0, 0), (-1, -1), 11),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 30))

    # Score with donut chart
    score_style = ParagraphStyle('ScoreTitle', fontName='Helvetica-Bold', fontSize=14, textColor=TRINTECH_BLUE)
    elements.append(Paragraph("Overall Security Score", score_style))
    elements.append(Spacer(1, 10))
    elements.append(DonutChart(90, score))
    elements.append(Spacer(1, 6))
    grade_text = f"Grade: {score_grade(score)}"
    elements.append(Paragraph(grade_text, ParagraphStyle('Grade', fontName='Helvetica-Bold',
                fontSize=14, textColor=score_color(score), alignment=TA_CENTER)))
    elements.append(Spacer(1, 30))

    # Confidentiality notice
    conf_style = ParagraphStyle('Conf', fontName='Helvetica', fontSize=9, textColor=TRINTECH_GRAY, alignment=TA_CENTER)
    elements.append(HRFlowable(width="80%", thickness=1, color=TRINTECH_GRAY))
    elements.append(Paragraph("🔒 NDA-CONFIDENTIAL", ParagraphStyle('ConfTitle', fontName='Helvetica-Bold',
              fontSize=10, textColor=TRINTECH_BLUE, alignment=TA_CENTER)))
    elements.append(Paragraph(
        "This report is confidential and intended solely for the use of the client named above. "
        "Unauthorized distribution or reproduction is strictly prohibited.", conf_style))


def _build_executive_summary(elements, client_name, target, eng_id, score, summary, findings):
    """Build the executive summary section."""
    elements.append(Paragraph("EXECUTIVE SUMMARY",
        ParagraphStyle('SectionTitle', fontName='Helvetica-Bold', fontSize=16,
                       textColor=TRINTECH_BLUE, spaceBefore=12, spaceAfter=8)))
    elements.append(HRFlowable(width="100%", thickness=1, color=TRINTECH_BLUE))
    elements.append(Spacer(1, 8))

    para = Paragraph(
        f"<b>TrinTech Digital Defense</b> conducted a comprehensive security audit of <b>{target}</b> "
        f"on behalf of <b>{client_name}</b>. This assessment evaluated the organization's network "
        f"security posture, identified vulnerabilities, and provides actionable recommendations.",
        ParagraphStyle('Body', fontName='Helvetica', fontSize=11, leading=16, spaceAfter=12)
    )
    elements.append(para)

    # Summary cards
    cards_data = [
        (str(score), "Security Score", score_color(score)),
        (str(len(findings)), "Total Findings", TRINTECH_BLUE),
        (str(summary.get("critical", 0)), "Critical", TRINTECH_RED),
        (str(summary.get("high", 0)), "High", TRINTECH_ORANGE),
        (str(summary.get("medium", 0)), "Medium", TRINTECH_YELLOW),
        (str(summary.get("low", 0)), "Low", TRINTECH_CYAN),
    ]

    for i in range(0, len(cards_data), 3):
        row = cards_data[i:i + 3]
        cell_items = []
        for value, label, color in row:
            color_bar = Drawing(8, 8)
            color_bar.add(Rect(0, 0, 8, 8, fillColor=color, strokeColor=None))
            cell_data = [
                color_bar,
                Paragraph(f"<b>{value}</b>", ParagraphStyle('CardVal', fontName='Helvetica-Bold',
                  fontSize=22, textColor=color)),
                Paragraph(f"<i>{label}</i>", ParagraphStyle('CardLabel', fontName='Helvetica',
                 fontSize=9, textColor=TRINTECH_GRAY))
            ]
            cell_table = Table(cell_data, colWidths=[12, 40, 70])
            cell_table.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('LEFTPADDING', (1, 0), (1, 0), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            cell_items.append(cell_table)

        row_tables = []
        for j in range(0, len(cell_items), 2):
            t1 = cell_items[j]
            t2 = cell_items[j + 1] if j + 1 < len(cell_items) else None
            if t2:
                row_tables.extend([t1, Spacer(1, 12), t2])
            else:
                row_tables.append(t1)

        row_table = Table(row_tables, colWidths=[2.2 * inch, 20, 2.2 * inch])
        row_table.setStyle([('VALIGN', (0, 0), (-1, -1), 'MIDDLE')])
        elements.append(row_table)
        elements.append(Spacer(1, 12))


def _build_findings_section(elements, findings):
    """Build the detailed findings section with CVE details."""
    elements.append(Paragraph("DETAILED FINDINGS",
        ParagraphStyle('SectionTitle', fontName='Helvetica-Bold', fontSize=16,
                       textColor=TRINTECH_BLUE, spaceBefore=12, spaceAfter=8)))
    elements.append(HRFlowable(width="100%", thickness=1, color=TRINTECH_BLUE))

    if not findings:
        elements.append(Paragraph("No security findings were identified during this assessment.",
            ParagraphStyle('Body', fontName='Helvetica', fontSize=11, textColor=TRINTECH_GREEN, spaceAfter=12)))
        return

    severity_groups = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
    for f in findings:
        sev = f.get("severity", "LOW")
        if sev in severity_groups:
            severity_groups[sev].append(f)

    for severity, items in severity_groups.items():
        if not items:
            continue

        sev_color = {"CRITICAL": TRINTECH_RED, "HIGH": TRINTECH_ORANGE, "MEDIUM": TRINTECH_YELLOW,
                     "LOW": TRINTECH_CYAN, "INFO": TRINTECH_GRAY}
        title = f"{severity} — {len(items)} Finding{'s' if len(items) > 1 else ''}"
        elements.append(Paragraph(title, ParagraphStyle('SubTitle', fontName='Helvetica-Bold',
                    fontSize=13, textColor=sev_color[severity], spaceBefore=16, spaceAfter=6)))

        for i, f in enumerate(items, 1):
            # Build finding card with optional CVE info
            cve_info = ""
            if f.get("cve_id") and f["cve_id"] != "N/A":
                cvss = f.get("cvss_score", "?")
                cve_info = f"<font color='#ef4444'><b>[{f['cve_id']}]</b> CVSS: {cvss}</font> "

            card_data = [
                [Paragraph(f"<b>{i}. {f.get('title', 'Finding')}</b>",
                           ParagraphStyle('FindingTitle', fontName='Helvetica-Bold', fontSize=10))],
            ]

            if cve_info:
                card_data.append([Paragraph(cve_info,
                    ParagraphStyle('CVEInfo', fontName='Helvetica', fontSize=8, textColor=TRINTECH_RED))])

            card_data.append([Paragraph(f"<b>What it means:</b> {f.get('description', 'N/A')}",
                           ParagraphStyle('FindingDesc', fontName='Helvetica', fontSize=9, leading=13))])

            if f.get("cve_description"):
                card_data.append([Paragraph(f"<b>CVE Details:</b> {f['cve_description']}",
                           ParagraphStyle('CveDesc', fontName='Helvetica-Oblique', fontSize=8, leading=12, textColor=TRINTECH_GRAY))])

            card_data.append([Paragraph(f"<b>What to do:</b> {f.get('remediation', 'Review with TrinTech team')}",
                           ParagraphStyle('FindingFix', fontName='Helvetica', fontSize=9, leading=13,
                                         textColor=TRINTECH_GREEN))])

            if f.get("port"):
                card_data.append([Paragraph(f"<b>Port:</b> {f['port']}",
                            ParagraphStyle('Port', fontName='Helvetica', fontSize=8, textColor=TRINTECH_GRAY))])

            if f.get("url"):
                card_data.append([Paragraph(f"<b>URL:</b> {f['url']}",
                            ParagraphStyle('Url', fontName='Helvetica', fontSize=8, textColor=TRINTECH_GRAY))])

            card_table = Table(card_data, colWidths=[6.3 * inch])
            card_table.setStyle(TableStyle([
                ('BOX', (0, 0), (-1, -1), 0.5, sev_color[severity]),
                ('BACKGROUND', (0, 0), (-1, -1), colors.Color(0x0a, 0x16, 0x28, 0.15)),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ]))
            elements.append(card_table)
            elements.append(Spacer(1, 4))


def _build_recon_findings(elements, recon_data):
    """Build the network reconnaissance findings section."""
    elements.append(Paragraph("NETWORK DISCOVERY",
        ParagraphStyle('SectionTitle', fontName='Helvetica-Bold', fontSize=16,
                       textColor=TRINTECH_BLUE, spaceBefore=12, spaceAfter=8)))
    elements.append(HRFlowable(width="100%", thickness=1, color=TRINTECH_BLUE))
    elements.append(Spacer(1, 4))

    modules = recon_data.get("modules", {})

    ports = modules.get("ports", [])
    if ports:
        elements.append(Paragraph(f"<b>Open Ports ({len(ports)}):</b>",
            ParagraphStyle('PortTitle', fontName='Helvetica-Bold', fontSize=11, spaceAfter=4)))

        port_data = [["Port", "Service", "Risk Level"]]
        for p in ports[:20]:
            port_num = p["port"] if isinstance(p, dict) else p
            svc = p.get("service", "unknown") if isinstance(p, dict) else "N/A"
            risk = "HIGH" if port_num in [21, 23, 135, 139, 445, 3389] else "MEDIUM" if port_num in [22, 80, 443] else "LOW"
            risk_color_hex = {"HIGH": "ef4444", "MEDIUM": "eab308", "LOW": "10b981"}.get(risk, "6b7280")
            port_data.append([str(port_num), svc, f"<font color='#{risk_color_hex}'>{risk}</font>"])

        port_table = Table(port_data, colWidths=[0.8 * inch, 2.5 * inch, 1.2 * inch])
        port_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), TRINTECH_NAVY),
            ('TEXTCOLOR', (0, 0), (-1, 0), TRINTECH_WHITE),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BACKGROUND', (0, 1), (-1, -1), TRINTECH_LIGHT_GRAY),
            ('GRID', (0, 0), (-1, -1), 0.5, TRINTECH_BORDER),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(port_table)
        elements.append(Spacer(1, 8))

    # Software versions
    versions = modules.get("versions", {})
    if versions:
        elements.append(Paragraph(f"<b>Detected Software Versions ({len(versions)}):</b>",
            ParagraphStyle('VerTitle', fontName='Helvetica-Bold', fontSize=11, spaceAfter=4)))
        ver_data = [["Port", "Software", "Version"]]
        for port_str, ver_tuple in versions.items():
            software, version = ver_tuple
            ver_data.append([str(port_str), software, version])
        ver_table = Table(ver_data, colWidths=[0.8 * inch, 2 * inch, 3.5 * inch])
        ver_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), TRINTECH_NAVY),
            ('TEXTCOLOR', (0, 0), (-1, 0), TRINTECH_WHITE),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BACKGROUND', (0, 1), (-1, -1), TRINTECH_LIGHT_GRAY),
            ('GRID', (0, 0), (-1, -1), 0.5, TRINTECH_BORDER),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(ver_table)
        elements.append(Spacer(1, 8))

    # SSL
    ssl_info = modules.get("ssl", {})
    if ssl_info:
        grade = ssl_info.get("grade", "N/A")
        elements.append(Paragraph(f"<b>SSL/TLS Grade: {grade}</b> — {ssl_info.get('protocol', 'N/A')}",
            ParagraphStyle('SSL', fontName='Helvetica-Bold', fontSize=11, textColor=TRINTECH_GREEN, spaceAfter=4)))
        cert = ssl_info.get("cert", {})
        if cert:
            days = cert.get("days_left", "N/A")
            elements.append(Paragraph(f"Certificate expires in {days} days",
                ParagraphStyle('CertInfo', fontName='Helvetica', fontSize=9, textColor=TRINTECH_GRAY)))

    # DNS
    dns = modules.get("dns_records", {})
    if dns:
        total = sum(len(v) for v in dns.values())
        elements.append(Paragraph(f"<b>DNS Records: {total} found across {len(dns)} types</b>",
            ParagraphStyle('DNS', fontName='Helvetica-Bold', fontSize=11, spaceAfter=4)))

    # Subdomains
    subs = modules.get("subdomains", [])
    if subs:
        elements.append(Paragraph(f"<b>Subdomains: {len(subs)} discovered</b>",
            ParagraphStyle('Sub', fontName='Helvetica-Bold', fontSize=11, spaceAfter=4)))


def _build_remediation_roadmap(elements, findings):
    """Build the remediation roadmap."""
    elements.append(Paragraph("RECOMMENDED ACTIONS",
        ParagraphStyle('SectionTitle', fontName='Helvetica-Bold', fontSize=16,
                       textColor=TRINTECH_BLUE, spaceBefore=12, spaceAfter=8)))
    elements.append(HRFlowable(width="100%", thickness=1, color=TRINTECH_BLUE))
    elements.append(Spacer(1, 4))

    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    high = [f for f in findings if f.get("severity") == "HIGH"]
    medium = [f for f in findings if f.get("severity") == "MEDIUM"]
    low = [f for f in findings if f.get("severity") == "LOW"]

    timeline = [
        ("Immediately (0-24 hours)", critical, TRINTECH_RED),
        ("This week (1-7 days)", high, TRINTECH_ORANGE),
        ("This month (1-4 weeks)", medium, TRINTECH_YELLOW),
        ("Ongoing improvement", low, TRINTECH_CYAN),
    ]

    for priority, items, color in timeline:
        if not items:
            continue
        elements.append(Paragraph(f"<b>{priority}</b>",
            ParagraphStyle('TimelineTitle', fontName='Helvetica-Bold', fontSize=12,
                           textColor=color, spaceBefore=8, spaceAfter=4)))

        r, g, b = int(color.red * 255), int(color.green * 255), int(color.blue * 255)
        hex_color = f"#{r:02x}{g:02x}{b:02x}"

        for item in items:
            bullets = [
                f"<bulletFontName>Helvetica</bulletFontName>",
                f"<bulletColor>{hex_color}</bulletColor>",
                f"<b>{item.get('title', 'Action')}</b> — {item.get('remediation', 'Review and fix')}",
            ]
            elements.append(Paragraph(" ".join(bullets),
                ParagraphStyle('Bullet', fontName='Helvetica', fontSize=9, leading=14, leftIndent=20, spaceAfter=2)))


def _build_conclusion(elements, client_name, eng_id):
    """Build the conclusion section."""
    elements.append(Spacer(1, 12))
    elements.append(HRFlowable(width="100%", thickness=1, color=TRINTECH_BLUE))
    elements.append(Spacer(1, 8))

    conclusion = (
        f"This assessment was performed by <b>TrinTech Digital Defense</b> as part of the security "
        f"engagement for <b>{client_name}</b> (Reference: {eng_id}). "
        f"The findings and recommendations in this report are based on automated scanning "
        f"and manual analysis conducted at the time of the assessment. "
        f"Security is an ongoing process — we recommend quarterly reassessments to ensure "
        f"continued protection against emerging threats."
    )
    elements.append(Paragraph(conclusion,
        ParagraphStyle('Conclusion', fontName='Helvetica', fontSize=11, leading=16, spaceAfter=12)))

    elements.append(Paragraph(
        "<b>Contact us:</b> "
        "Email: trintechdigitaldefense@gmail.com | "
        "WhatsApp: +1 (868) 362-0679 | "
        "Website: trintechdigitaldefense.github.io",
        ParagraphStyle('Contact', fontName='Helvetica', fontSize=10, textColor=TRINTECH_BLUE, spaceAfter=4)))


def _build_footer_elements(elements):
    """Add standard footer elements."""
    elements.append(Spacer(1, 12))
    elements.append(HRFlowable(width="100%", thickness=1, color=TRINTECH_BORDER))

    footer_text = f"TrinTech Digital Defense 🛡️ {datetime.now().strftime('%Y-%m-%d')} | Confidential Report"
    elements.append(Paragraph(footer_text,
        ParagraphStyle('Footer', fontName='Helvetica', fontSize=8, textColor=TRINTECH_GRAY,
                       alignment=TA_CENTER)))
    elements.append(Paragraph("DEFEND. DETECT. DOMINATE.",
        ParagraphStyle('Tagline', fontName='Helvetica-Bold', fontSize=8,
                       textColor=TRINTECH_BLUE, alignment=TA_CENTER)))


def _build_remediation_guide(elements, findings):
    """Build the Remediation Guide appendix — additional to the main report."""
    elements.append(Paragraph("REMEDIATION GUIDE",
        ParagraphStyle('SectionTitle', fontName='Helvetica-Bold', fontSize=18,
                       textColor=TRINTECH_BLUE, spaceBefore=0, spaceAfter=4)))
    elements.append(Paragraph("Technical Remediation Reference — Appendix A",
        ParagraphStyle('SubTitle', fontName='Helvetica', fontSize=11, textColor=TRINTECH_GRAY, spaceAfter=12)))
    elements.append(HRFlowable(width="100%", thickness=1, color=TRINTECH_BLUE))

    if not findings:
        elements.append(Paragraph("No remediation actions required.",
            ParagraphStyle('Body', fontName='Helvetica', fontSize=11, textColor=TRINTECH_GREEN, spaceAfter=12)))
        return

    # Group findings by remediation type and provide detailed steps
    sections = {
        "Firewall & Network Access": [],
        "Web Server Configuration": [],
        "SSL/TLS Hardening": [],
        "Cookie & Session Security": [],
        "CORS & Access Control": [],
        "Application Security Headers": [],
        "Software Updates": [],
        "General Hardening": [],
    }

    for f in findings:
        title = f.get("title", "").lower()
        remediation = f.get("remediation", "").lower()
        desc = f.get("description", "").lower()
        port = f.get("port")

        # Categorize
        if port in [21, 23, 135, 139, 445, 3389, 512, 513, 514] or "firewall" in remediation or "restrict" in remediation:
            sections["Firewall & Network Access"].append(f)
        elif "cookie" in title or "session" in title or "httponly" in remediation or "samesite" in remediation or "secure flag" in remediation:
            sections["Cookie & Session Security"].append(f)
        elif "cors" in title:
            sections["CORS & Access Control"].append(f)
        elif "header" in title or "security header" in title or "x-frame" in title or "x-content" in title or "x-xss" in title or "referrer" in title or "permissions" in title or "content-security" in title:
            sections["Application Security Headers"].append(f)
        elif "http://" in desc or "http://" in remediation or "ssl" in title or "tls" in title or "https" in remediation or "encrypt" in remediation:
            sections["SSL/TLS Hardening"].append(f)
        elif "update" in remediation or "version" in title or "outdated" in desc or "upgrade" in remediation or "latest" in remediation or "patch" in remediation or "backdoor" in title:
            sections["Software Updates"].append(f)
        elif "nginx" in remediation or "apache" in remediation or "server" in remediation or "config" in remediation or "redirect" in remediation:
            sections["Web Server Configuration"].append(f)
        else:
            sections["General Hardening"].append(f)

    for section_name, items in sections.items():
        if not items:
            continue

        elements.append(Paragraph(f"{section_name}",
            ParagraphStyle('SectionHeader', fontName='Helvetica-Bold', fontSize=13,
                           textColor=TRINTECH_BLUE, spaceBefore=12, spaceAfter=6)))

        for item in items:
            # Find the corresponding fix config
            fix_text = _get_remediation_config(item)

            # Build the card
            card_data = [
                [Paragraph(f"<b>{item.get('title', 'Finding')}</b>",
                           ParagraphStyle('RemTitle', fontName='Helvetica-Bold', fontSize=10, textColor=TRINTECH_NAVY))],
            ]

            if item.get("cve_id") and item["cve_id"] != "N/A":
                card_data.append([Paragraph(f"<font color='#ef4444'><b>{item['cve_id']}</b> (CVSS: {item.get('cvss_score', '?')})</font>",
                    ParagraphStyle('CVEInfo', fontName='Helvetica', fontSize=8, textColor=TRINTECH_RED))])

            if fix_text:
                card_data.append([Paragraph("<b>Remediation:</b>",
                    ParagraphStyle('FixLabel', fontName='Helvetica-Bold', fontSize=9, textColor=TRINTECH_GREEN, spaceBefore=4))])
                card_data.append([Paragraph(fix_text,
                    ParagraphStyle('FixCode', fontName='Courier', fontSize=8, leading=12,
                                   textColor=TRINTECH_NAVY,
                                   borderWidth=0.5, borderColor=TRINTECH_BORDER,
                                   borderPadding=4, backColor=TRINTECH_LIGHT_GRAY))])
            else:
                card_data.append([Paragraph(f"<b>Remediation:</b> {item.get('remediation', 'Review and fix')}",
                    ParagraphStyle('FixPlain', fontName='Helvetica', fontSize=9, textColor=TRINTECH_GREEN, spaceBefore=4))])

            card_table = Table(card_data, colWidths=[6.3 * inch])
            card_table.setStyle(TableStyle([
                ('BOX', (0, 0), (-1, -1), 0.5, TRINTECH_BLUE),
                ('BACKGROUND', (0, 0), (-1, -1), TRINTECH_WHITE),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ]))
            elements.append(card_table)
            elements.append(Spacer(1, 4))

    # Add closing note
    elements.append(Spacer(1, 12))
    elements.append(HRFlowable(width="100%", thickness=1, color=TRINTECH_BLUE))
    elements.append(Paragraph(
        "This remediation guide provides actionable technical steps to address the findings above. "
        "For assistance with implementation, contact TrinTech Digital Defense at "
        "<b>trintechdigitaldefense@gmail.com</b> or <b>WhatsApp: +1 (868) 362-0679</b>.",
        ParagraphStyle('GuideFooter', fontName='Helvetica', fontSize=10, textColor=TRINTECH_GRAY, spaceAfter=8)))
    elements.append(Paragraph("DEFEND. DETECT. DOMINATE.",
        ParagraphStyle('Tagline2', fontName='Helvetica-Bold', fontSize=8,
                       textColor=TRINTECH_BLUE, alignment=TA_CENTER)))


def _get_remediation_config(finding):
    """Generate specific remediation configuration based on the finding."""
    title = finding.get("title", "").lower()
    desc = finding.get("description", "").lower()

    # Nginx header configs
    if "x-content-type-options" in title or "mime sniffing" in desc:
        return ("<i>nginx:</i><br/>"
                "<b>add_header X-Content-Type-Options nosniff;</b><br/><br/>"
                "<i>Apache:</i><br/>"
                "<b>Header always set X-Content-Type-Options \"nosniff\"</b>")

    if "x-xss-protection" in title or "xss" in desc and "header" in title:
        return ("<i>nginx:</i><br/>"
                "<b>add_header X-XSS-Protection \"1; mode=block\";</b><br/><br/>"
                "<i>Apache:</i><br/>"
                "<b>Header always set X-XSS-Protection \"1; mode=block\"</b>")

    if "strict-transport-security" in title or "hsts" in desc:
        return ("<i>nginx:</i><br/>"
                "<b>add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;</b><br/><br/>"
                "<i>Apache:</i><br/>"
                "<b>Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"</b>")

    if "x-frame-options" in title or "clickjack" in desc:
        return ("<i>nginx:</i><br/>"
                "<b>add_header X-Frame-Options \"DENY\";</b><br/><br/>"
                "<i>Apache:</i><br/>"
                "<b>Header always set X-Frame-Options \"DENY\"</b>")

    if "content-security-policy" in title or "csp" in desc:
        return ("<i>nginx:</i><br/>"
                "<b>add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';\" always;</b><br/><br/>"
                "<i>Apache:</i><br/>"
                "<b>Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';\"</b>")

    if "referrer-policy" in title or "referrer" in desc and "policy" in title:
        return ("<i>nginx:</i><br/>"
                "<b>add_header Referrer-Policy \"strict-origin-when-cross-origin\";</b><br/><br/>"
                "<i>Apache:</i><br/>"
                "<b>Header always set Referrer-Policy \"strict-origin-when-cross-origin\"</b>")

    if "permissions-policy" in title or "permissions" in desc and "policy" in title:
        return ("<i>nginx:</i><br/>"
                "<b>add_header Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=()\";</b><br/><br/>"
                "<i>Apache:</i><br/>"
                "<b>Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=()\"</b>")

    # Cookie security
    if "cookie" in title or "secure flag" in desc or "samesite" in desc or "httponly" in desc:
        return ("<i>Application code (example):</i><br/>"
                "<b>Set-Cookie: session_id=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600</b><br/><br/>"
                "Ensure all cookies have: Secure, HttpOnly, SameSite=Strict attributes")

    # CORS
    if "cors" in title:
        return ("<i>nginx:</i><br/>"
                "<b>add_header Access-Control-Allow-Origin \"https://trusted-domain.com\";</b><br/>"
                "<b>add_header Access-Control-Allow-Methods \"GET, POST\";</b><br/>"
                "<b>add_header Access-Control-Allow-Credentials \"true\";</b><br/><br/>"
                "Never use wildcard (*) with credentials. Whitelist specific domains.")

    # Open redirect
    if "redirect" in title:
        return ("Implement server-side allowlist for redirect destinations:<br/>"
                "<b>Allowed: /dashboard, /profile, /settings</b><br/>"
                "<b>Blocked: http://evil.com, //evil.com</b><br/><br/>"
                "Validate redirect parameter against a whitelist before redirecting.")

    # Environment files
    if "env" in title and "exposed" in desc:
        return ("<i>nginx:</i><br/>"
                "<b>location /.env { deny all; return 404; }</b><br/><br/>"
                "<i>Apache:</i><br/>"
                "<b>&lt;FilesMatch \"^\\.env\"&gt;<br/>  Require all denied<br/>&lt;/FilesMatch&gt;</b>")

    # Git config
    if "git" in title and "exposed" in desc:
        return ("<i>nginx:</i><br/>"
                "<b>location /.git { deny all; return 404; }</b><br/><br/>"
                "Remove sensitive files from public access. Use .gitignore properly.")

    # Database ports
    if "mysql" in title and "exposed" in desc:
        return ("Bind MySQL to localhost only:<br/>"
                "<i>/etc/mysql/mysql.conf.d/mysqld.cnf:</i><br/>"
                "<b>bind-address = 127.0.0.1</b><br/><br/>"
                "Then restart: <b>systemctl restart mysql</b>")

    if "redis" in title and "exposed" in desc:
        return ("Bind Redis to localhost and require password:<br/>"
                "<i>/etc/redis/redis.conf:</i><br/>"
                "<b>bind 127.0.0.1 ::1</b><br/>"
                "<b>requirepass &lt;strong-password&gt;</b><br/><br/>"
                "Then restart: <b>systemctl restart redis</b>")

    if "mongodb" in title and "exposed" in desc:
        return ("Enable authentication in MongoDB:<br/>"
                "<i>/etc/mongod.conf:</i><br/>"
                "<b>security:</b><br/>"
                "<b>  authorization: enabled</b><br/><br/>"
                "Create admin user and restart: <b>systemctl restart mongod</b>")

    if "elasticsearch" in title and "exposed" in desc:
        return ("Enable X-Pack security in Elasticsearch:<br/>"
                "<i>/etc/elasticsearch/elasticsearch.yml:</i><br/>"
                "<b>xpack.security.enabled: true</b><br/><br/>"
                "Set passwords for built-in users: <b>elasticsearch-setup-passwords auto</b>")

    if "memcached" in title and "exposed" in desc:
        return ("Bind Memcached to localhost and disable UDP:<br/>"
                "<i>/etc/sysconfig/memcached (RHEL) or /etc/memcached.conf (Debian):</i><br/>"
                "<b>-l 127.0.0.1</b><br/>"
                "<b>-d</b> (disable UDP)")

    if "vnc" in title and "open" in desc:
        return ("Set strong VNC password and restrict access:<br/>"
                "<i>~/.vnc/config:</i><br/>"
                "<b>SecurityTypes=VncAuth</b><br/><br/>"
                "Use SSH tunnel instead of exposing VNC directly to the internet.")

    # RDP
    if "rdp" in title:
        return ("Enable Network Level Authentication:<br/>"
                "Group Policy → Computer Configuration → Administrative Templates → Windows Components → Remote Desktop Services → <b>Require NLA</b><br/><br/>"
                "Restrict RDP access to VPN/IP whitelist via firewall.")

    # Telnet
    if "telnet" in title:
        return ("Disable Telnet service:<br/>"
                "<b>systemctl disable telnet</b><br/>"
                "<b>apt purge telnetd</b><br/><br/>"
                "Use SSH instead.")

    # FTP
    if "ftp" in title:
        return ("Disable plain FTP and use SFTP/FTPS:<br/>"
                "<i>vsftpd.conf:</i><br/>"
                "<b>anonymous_enable=NO</b><br/>"
                "<b>local_enable=YES</b><br/>"
                "<b>ssl_enable=YES</b><br/><br/>"
                "Or switch to SFTP: <b>systemctl enable sshd</b> (SSH includes SFTP)")

    return None  # No specific config available


if __name__ == "__main__":
    # Test with sample data
    sample_eng = {
        "id": "ENG-20260101-ABC123",
        "client_name": "Test Corp",
        "target": "example.com",
        "service": "micro",
        "created": datetime.now().isoformat(),
    }
    sample_data = {
        "recon": {"modules": {"ports": [], "banners": {}, "dns_records": {}, "subdomains": []}},
        "web": {"endpoints": [], "security_findings": [], "summary": {}},
        "osint": {"modules": {}},
        "vuln": {"findings": [], "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0}},
    }
    filename = generate_report(sample_eng, sample_data)
    if filename:
        print(f"Report generated: {filename}")
