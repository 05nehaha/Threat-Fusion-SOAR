from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
import os

def generate_pdf_report(
    target,
    nmap_data,
    nikto_data,
    filename,
    vulnerabilities,
    attacks, 
    cve_data,
    crawled_urls,
    security_score=100, 
    risk_level="LOW"    
):
    report_dir = os.path.join(os.path.dirname(__file__), 'scans', 'reports')
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)

    path = os.path.join(report_dir, filename)
    doc = SimpleDocTemplate(path, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Logic for CRITICAL color support
    score_color = colors.red
    if security_score >= 80: score_color = colors.green
    elif security_score >= 50: score_color = colors.orange
    
    score_style = ParagraphStyle(
        'ScoreStyle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=score_color,
        alignment=1,
        spaceAfter=20
    )
    
    story = []
    story.append(Paragraph(f"Vulnerability Assessment Report: {target}", styles['Title']))
    story.append(Spacer(1, 10))
    story.append(Paragraph(f"SECURITY SCORE: {security_score}/100", score_style))
    story.append(Paragraph(f"OVERALL RISK LEVEL: {risk_level.upper()}", styles['Normal']))
    story.append(Spacer(1, 12))

    # Nmap Table
    story.append(Paragraph("1. Network Scan Results (Nmap)", styles['Heading2']))
    table_data = [['Port', 'Service', 'Version', 'State']]
    for item in nmap_data:
        table_data.append([str(item.get('port', '')), item.get('name', ''), item.get('version', ''), item.get('state', '')])
    
    table = Table(table_data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    story.append(table)

    # Nikto Results
    story.append(Spacer(1, 20))
    story.append(Paragraph("2. Web Vulnerability Results (Nikto)", styles['Heading2']))
    nikto_clean = str(nikto_data).replace('\n', '<br/>')[:5000] 
    story.append(Paragraph(nikto_clean, styles['Code']))

    # Endpoints
    story.append(Spacer(1, 20))
    story.append(Paragraph("3. Crawled Website Endpoints", styles['Heading2']))
    for url in (crawled_urls or ["No endpoints found"]):
        story.append(Paragraph(f"- {url}", styles['Normal']))

    # CVE Intelligence
    story.append(Spacer(1, 20))
    story.append(Paragraph("4. Vulnerability Intelligence (CVE Mapping)", styles['Heading2']))
    if not cve_data:
        story.append(Paragraph("No relevant CVEs identified.", styles['Normal']))
    else:
        for item in cve_data:
            story.append(Paragraph(f"<b>{item['vuln']}</b>", styles['Normal']))
            for cve in item['cve']:
                story.append(Paragraph(f"- {cve}", styles['Normal']))

    # Mitigations
    story.append(Spacer(1, 20))
    story.append(Paragraph("5. Attack Possibilities & Mitigation", styles['Heading2']))
    for item in attacks:
        story.append(Paragraph(f"<b>Attack:</b> {item.get('Attack', 'Unknown')}", styles['Normal']))
        story.append(Paragraph(f"<b>Mitigation:</b> {item.get('Mitigation', 'Unknown')}", styles['Normal']))
        story.append(Spacer(1, 10))

    doc.build(story)
    return path