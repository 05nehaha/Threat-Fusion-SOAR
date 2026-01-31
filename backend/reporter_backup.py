from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
import os

def generate_pdf_report(target, nmap_data, nikto_data, filename):
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
    title = Paragraph(f"Vulnerability Assessment Report: {target}", styles['Title'])
    story.append(title)
    story.append(Spacer(1, 12))

    # 2. Nmap Results Table
    story.append(Paragraph("1. Network Scan Results (Nmap)", styles['Heading2']))
    
    # Table Header
    data = [['Port', 'Service', 'Version', 'State']]
    for item in nmap_data:
        data.append([str(item['port']), item['name'], item['version'], item['state']])

    # Create and Style the Table
    t = Table(data)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
    ]))
    story.append(t)
    story.append(Spacer(1, 24))

    # 3. Nikto Results (Raw Text)
    story.append(Paragraph("2. Web Vulnerability Results (Nikto)", styles['Heading2']))
    
    # Since Nikto output is long, we wrap it in a smaller font
    nikto_style = styles['Code']
    nikto_para = Paragraph(nikto_data.replace('\n', '<br/>'), nikto_style)
    story.append(nikto_para)

    # Build the PDF
    doc.build(story)
    print(f"✅ PDF Report generated at: {path}")
    return path

if __name__ == "__main__":
    # Quick Test
    test_nmap = [{'port': 80, 'name': 'http', 'version': 'Apache 2.4', 'state': 'open'}]
    test_nikto = "- Nikto v2.5.0\n- Target IP: 127.0.0.1\n- OSVDB-3092: /admin/ login found."
    generate_pdf_report("127.0.0.1", test_nmap, test_nikto, "test_report.pdf")