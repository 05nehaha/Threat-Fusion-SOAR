from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
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
    attacks,  # <--- Modified: This now contains both Attack AND Mitigation data
    cve_data, # <--- Shifted position (removed 'mitigations' arg)
    crawled_urls
):
    """Generates a professional forensic PDF report."""

    # Ensure the reports directory exists
    report_dir = os.path.join(os.path.dirname(__file__), 'scans', 'reports')
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)

    path = os.path.join(report_dir, filename)
    doc = SimpleDocTemplate(path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # 1. Title
    story.append(Paragraph(f"Vulnerability Assessment Report: {target}", styles['Title']))
    story.append(Spacer(1, 12))

    # 2. Network Scan Results (Nmap)
    story.append(Paragraph("1. Network Scan Results (Nmap)", styles['Heading2']))

    table_data = [['Port', 'Service', 'Version', 'State']]
    # Handle case where nmap_data might be a string error message
    if isinstance(nmap_data, list):
        for item in nmap_data:
            table_data.append([
                str(item.get('port', '')),
                item.get('name', ''),
                item.get('version', ''),
                item.get('state', '')
            ])
    else:
        # Fallback if Nmap failed
        table_data.append(["-", "Scan Failed/Blocked", "-", "-"])

    table = Table(table_data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
    ]))

    story.append(table)
    story.append(Spacer(1, 20))

    # 3. Web Vulnerability Results (Nikto)
    story.append(Paragraph("2. Web Vulnerability Results (Nikto)", styles['Heading2']))
    
    # Safe handling of Nikto output
    nikto_clean = str(nikto_data).replace('\n', '<br/>')[:5000] # Limit length to prevent crash
    nikto_para = Paragraph(nikto_clean, styles['Code'])
    story.append(nikto_para)

    # 3. Crawled Website Endpoints
    story.append(Spacer(1, 20))
    story.append(Paragraph("3. Crawled Website Endpoints", styles['Heading2']))

    if not crawled_urls:
        story.append(Paragraph("No crawlable endpoints found (site may block automated crawling or use dynamic content).", styles['Normal']))
    else:
        for url in crawled_urls:
            story.append(Paragraph(f"- {url}", styles['Normal']))

    # 4. Vulnerabilities Detected
    story.append(Spacer(1, 20))
    story.append(Paragraph("4. Vulnerabilities Detected", styles['Heading2']))

    if not vulnerabilities:
        story.append(Paragraph("No specific vulnerabilities detected.", styles['Normal']))
    else:
        for v in vulnerabilities:
            story.append(Paragraph(f"- {v}", styles['Normal']))

    # 5. Vulnerability Intelligence (CVE Mapping)
    story.append(Spacer(1, 20))
    story.append(Paragraph("5. Vulnerability Intelligence (CVE Mapping)", styles['Heading2']))

    if not cve_data:
        story.append(Paragraph("No relevant CVEs identified.", styles['Normal']))
    else:
        for item in cve_data:
            story.append(Paragraph(f"<b>{item['vuln']}</b>", styles['Normal']))
            for cve in item['cve']:
                story.append(Paragraph(f"- {cve}", styles['Normal']))
            story.append(Spacer(1, 5))

    # 6. Attack Possibilities & Mitigation
    story.append(Spacer(1, 20))
    story.append(Paragraph("6. Attack Possibilities & Mitigation", styles['Heading2']))

    if not attacks:
        story.append(Paragraph("No specific attack vectors identified based on current scan results.", styles['Normal']))
    else:
        # ✅ UPDATED LOGIC: Iterate through the dictionary list
        for item in attacks:
            story.append(Paragraph(f"<b>Attack:</b> {item.get('Attack', 'Unknown')}", styles['Normal']))
            story.append(Paragraph(f"<b>Mitigation:</b> {item.get('Mitigation', 'Unknown')}", styles['Normal']))
            story.append(Spacer(1, 10))

    # Build PDF
    try:
        doc.build(story)
        print(f"✅ PDF Report generated at: {path}")
        return path
    except Exception as e:
        print(f"❌ PDF Generation Error: {e}")
        return None