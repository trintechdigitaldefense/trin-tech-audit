# TrinTech Digital Defense — Professional PDF Report Generator
# Generates client-ready, non-technical security audit reports

import os
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
        PageBreak, KeepTogether, HRFlowable, Image
    )
    from reportlab.graphics.shapes import Drawing, Rect, Line, Wedge, Circle
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
    all_findings = []

    # From recon
    recon_modules = recon_data.get("modules", {})
    ports = recon_modules.get("ports", [])
    banners = recon_modules.get("banners", {})
    dns_records = recon_modules.get("dns_records", {})
    subdomains = recon_modules.get("subdomains", [])
    ssl_info = recon_modules.get("ssl", {})
    whois_info = recon_modules.get("whois", {})

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
        if "security_findings" in web_data:
            web_findings.extend(web_data["security_findings"])

    # Merge all findings (deduplicate by title)
    seen_titles = set()
    for f in vuln_findings:
        if f["title"] not in seen_titles:
            all_findings.append(f)
            seen_titles.add(f["title"])
    for f in web_findings:
        if f.get("title") and f["title"] not in seen_titles:
            all_findings.append(f)
            seen_titles.add(f["title"])

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "INFO"), 9))

    summary = vuln_data.get("summary", {})

    # Calculate score
    score = calculate_security_score(summary)

    # Generate PDF
    output_dir = Path(__file__).parent / "reports"
    output_dir.mkdir(exist_ok=True)
    filename = f"{eng_id}_{client_name.replace(' ', '_')[:20]}_Audit_Report.pdf"
    filepath = output_dir / filename

    doc = SimpleDocTemplate(
        str(filepath),
        pagesize=letter,
        topMargin=0.5*inch,
        bottomMargin=0.5*inch,
        leftMargin=0.7*inch,
        rightMargin=0.7*inch,
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

    build_result = doc.build(elements)
    return filename


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


def _build_cover_page(elements, client_name, target, eng_id, created, service, score):
    """Build the cover page."""
    # Title block
    title_style = ParagraphStyle('CoverTitle', parent=None, fontName='Helvetica-Bold',
                                  fontSize=28, textColor=TRINTECH_BLUE, spaceAfter=12, alignment=TA_LEFT)
    elements.append(Paragraph(f"SECURITY AUDIT REPORT", title_style))

    subtitle_style = ParagraphStyle('CoverSub', parent=None, fontName='Helvetica',
                                     fontSize=16, textColor=TRINTECH_CYAN, spaceAfter=24)
    elements.append(Paragraph(f"Network & Infrastructure Assessment", subtitle_style))

    # Divider
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

    info_table = Table(client_info, colWidths=[2.5*inch, 4.5*inch])
    info_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('FONTSIZE', (0, 0), (-1, -1), 11),
    ]))
    elements.append(info_table)

    elements.append(Spacer(1, 30))

    # Score card
    score_style = ParagraphStyle('ScoreTitle', fontName='Helvetica-Bold', fontSize=14, textColor=TRINTECH_BLUE)
    elements.append(Paragraph("Overall Security Score", score_style))

    score_bg_color = score_color(score)
    score_rect = Drawing(150, 150)
    score_rect.add(Rect(0, 0, 150, 150, fillColor=TRINTECH_NAVY, strokeColor=None))
    score_rect.add(Rect(2, 2, 146, 146, fillColor=score_bg_color, strokeColor=None))
    score_text = Paragraph(f"{score}", ParagraphStyle('ScoreNum', fontName='Helvetica-Bold',
            fontSize=48, textColor=TRINTECH_WHITE, alignment=TA_CENTER))
    from reportlab.platypus import Flowable
    class ScoreCircle(Flowable):
        def __init__(self, diameter, score_val):
            Flowable.__init__(self)
            self.diameter = diameter
            self.score_val = score_val
            self.width = diameter
            self.height = diameter

        def draw(self):
            self.canv.saveState()
            self.canv.setFillColor(score_color(self.score_val))
            self.canv.circle(self.width/2, self.height/2, self.diameter/2, fill=1)
            self.canv.setFillColor(TRINTECH_WHITE)
            self.canv.setFont('Helvetica-Bold', 36)
            self.canv.drawCentredString(self.width/2, self.height/2 + 12, str(self.score_val))
            self.canv.setFont('Helvetica', 9)
            self.canv.drawCentredString(self.width/2, self.height/2 - 16, "out of 100")
            self.canv.restoreState()

    elements.append(Spacer(1, 10))
    elements.append(ScoreCircle(80, score))
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
                       textColor=TRINTECH_BLUE, spaceBefore=12, spaceAfter=8,
                       borderWidth=0, borderColor=TRINTECH_BLUE, borderPadding=0)))
    elements.append(HRFlowable(width="100%", thickness=1, color=TRINTECH_BLUE))

    elements.append(Spacer(1, 8))

    # Summary paragraph
    para = Paragraph(
        f"<b>TrinTech Digital Defense</b> conducted a comprehensive security audit of <b>{target}</b> "
        f"on behalf of <b>{client_name}</b>. This assessment evaluated the organization's network "
        f"security posture, identified vulnerabilities, and provides actionable recommendations.",
        ParagraphStyle('Body', fontName='Helvetica', fontSize=11, leading=16, spaceAfter=12)
    )
    elements.append(para)

    # Score summary cards
    cards_data = [
        (str(score), "Security Score", score_color(score)),
        (str(len(findings)), "Total Findings", TRINTECH_BLUE),
        (str(summary.get("critical", 0)), "Critical", TRINTECH_RED),
        (str(summary.get("high", 0)), "High", TRINTECH_ORANGE),
        (str(summary.get("medium", 0)), "Medium", TRINTECH_YELLOW),
        (str(summary.get("low", 0)), "Low", TRINTECH_CYAN),
    ]

    card_width = 1.6 * inch
    card_height = 2.2 * inch
    card_data = []
    for value, label, color in cards_data:
        card_data.append([{
            "value": value, "label": label, "color": color
        }])

    # Create a table for the cards
    col_widths = [card_width] * 6
    card_table_data = []
    for col in range(6):
        c = cards_data[col]
        cell = f"<para align='center'><font color='#ffffff'><b>{c[0]}</b></font><br/>"
        cell += f"<font color='#cccccc' size='9'>{c[1]}</font></para>"
        card_table_data.append([Paragraph(cell, ParagraphStyle('CardCell', fontName='Helvetica-Bold',
                  fontSize=20, textColor=TRINTECH_WHITE))])

    # Actually let's build simpler cards
    # Each card: color bar + value + label
    card_items = []
    for value, label, color in cards_data:
        # Color indicator
        color_bar = Drawing(8, 8)
        color_bar.add(Rect(0, 0, 8, 8, fillColor=color, strokeColor=None))

        cell_data = [
            [color_bar, Paragraph(f"<b>{value}</b>", ParagraphStyle('CardVal', fontName='Helvetica-Bold',
              fontSize=22, textColor=color)),
             Paragraph(f"<i>{label}</i>", ParagraphStyle('CardLabel', fontName='Helvetica',
              fontSize=9, textColor=TRINTECH_GRAY))]
        ]
        cell_table = Table(cell_data, colWidths=[12, 40, 70])
        cell_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (1, 0), (1, 0), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        card_items.append(cell_table)

    # Split cards into rows (3 per row)
    for i in range(0, len(card_items), 3):
        row = card_items[i:i+3]
        row_table = Table(
            [[item, Spacer(1, 12), item2] for item, item2 in zip(row[::2], row[1::2] + [None] * (len(row)//2 - len(row)//2)) if item2],
            colWidths=[2.2*inch, 20, 2.2*inch]
        )
        row_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(row_table)
        elements.append(Spacer(1, 12))


def _build_findings_section(elements, findings):
    """Build the detailed findings section."""
    elements.append(Paragraph("DETAILED FINDINGS",
        ParagraphStyle('SectionTitle', fontName='Helvetica-Bold', fontSize=16,
                       textColor=TRINTECH_BLUE, spaceBefore=12, spaceAfter=8)))
    elements.append(HRFlowable(width="100%", thickness=1, color=TRINTECH_BLUE))

    if not findings:
        elements.append(Paragraph("No security findings were identified during this assessment.",
            ParagraphStyle('Body', fontName='Helvetica', fontSize=11, textColor=TRINTECH_GREEN, spaceAfter=12)))
        return

    # Group by severity
    severity_groups = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for f in findings:
        sev = f.get("severity", "LOW")
        if sev in severity_groups:
            severity_groups[sev].append(f)

    for severity, items in severity_groups.items():
        if not items:
            continue

        sev_color = {"CRITICAL": TRINTECH_RED, "HIGH": TRINTECH_ORANGE, "MEDIUM": TRINTECH_YELLOW, "LOW": TRINTECH_CYAN}
        title = f"{severity} — {len(items)} Finding{'s' if len(items) > 1 else ''}"
        elements.append(Paragraph(title, ParagraphStyle('SubTitle', fontName='Helvetica-Bold',
                    fontSize=13, textColor=sev_color[severity], spaceBefore=16, spaceAfter=6)))

        for i, f in enumerate(items, 1):
            # Finding card
            card_data = [
                [Paragraph(f"<b>{i}. {f.get('title', 'Finding')}</b>",
                           ParagraphStyle('FindingTitle', fontName='Helvetica-Bold', fontSize=10))],
                [Paragraph(f"<b>What it means:</b> {f.get('description', 'N/A')}",
                           ParagraphStyle('FindingDesc', fontName='Helvetica', fontSize=9, leading=13))],
                [Paragraph(f"<b>What to do:</b> {f.get('remediation', 'Review with TrinTech team')}",
                           ParagraphStyle('FindingFix', fontName='Helvetica', fontSize=9, leading=13,
                                         textColor=TRINTECH_GREEN))],
            ]
            if f.get("port"):
                card_data.append([Paragraph(f"<b>Port:</b> {f['port']}",
                            ParagraphStyle('Port', fontName='Helvetica', fontSize=8, textColor=TRINTECH_GRAY))])

            card_table = Table(card_data, colWidths=[6.3*inch])
            card_table.setStyle(TableStyle([
                ('BOX', (0, 0), (-1, -1), 0.5, sev_color[severity]),
                ('BACKGROUND', (0, 0), (-1, -1), colors.Color(0x0a, 0x16, 0x28, 0.15)),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
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

    # Open ports
    ports = modules.get("ports", [])
    if ports:
        elements.append(Paragraph(f"<b>Open Ports ({len(ports)}):</b>",
            ParagraphStyle('PortTitle', fontName='Helvetica-Bold', fontSize=11, spaceAfter=4)))

        # Simple table
        port_data = [["Port", "Service", "Risk Level"]]
        for p in ports[:20]:  # Limit to 20
            port_num = p["port"] if isinstance(p, dict) else p
            svc = p.get("service", "unknown") if isinstance(p, dict) else "N/A"
            risk = "HIGH" if port_num in [21, 23, 135, 139, 445, 3389] else "MEDIUM" if port_num in [22, 80, 443] else "LOW"
            risk_color = {"HIGH": TRINTECH_RED, "MEDIUM": TRINTECH_YELLOW, "LOW": TRINTECH_GREEN}.get(risk, TRINTECH_GRAY)
            port_data.append([str(port_num), svc, f"<font color='#{'ef4444' if risk == 'HIGH' else 'eab308' if risk == 'MEDIUM' else '10b981'}'>{risk}</font>"])

        port_table = Table(port_data, colWidths=[0.8*inch, 2.5*inch, 1.2*inch])
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

    # SSL grade
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

    # Group by priority
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
