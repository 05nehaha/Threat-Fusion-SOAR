from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)
import os
import re

def generate_pdf_report(
    target, nmap_data, nikto_data, filename, vulnerabilities, attacks, 
    cve_data, crawled_urls, security_score=100, risk_level="LOW"    
):
    report_dir = os.path.join(os.path.dirname(__file__), 'scans', 'reports')
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)

    path = os.path.join(report_dir, filename)
    doc = SimpleDocTemplate(path, pagesize=letter)
    styles = getSampleStyleSheet()

    # --- 🧠 100% DYNAMIC BEHAVIORAL ENGINE ---
    nikto_string = str(nikto_data).lower()
    
    # 1. Edge Mitigation Detection (WAF/CDN)
    is_waf_protected = any(waf in nikto_string for waf in ["cloudflare", "imperva", "akamai", "barracuda", "cloudfront"])

    # 2. Autonomous High-Value Target Detection (Behavior, not URL)
    is_high_value = False
    auth_indicators = ['login', 'signin', 'admin', 'dashboard', 'auth', 'account']
    if crawled_urls and any(any(ind in url.lower() for ind in auth_indicators) for url in crawled_urls):
        is_high_value = True
    if "session" in nikto_string or "token" in nikto_string:
        is_high_value = True

    # Filter False Positives
    filtered_attacks = []
    SENSITIVE_COOKIES = ["jsessionid", "phpsessid", "aspsessionid", "auth_token", "wordpress_logged_in", "session"]
    if attacks:
        for attack in attacks:
            name = attack.get('Attack', '')
            if "Clickjacking" in name and "x-frame-options: sameorigin" in nikto_string: continue 
            if "Cross-Domain Policy" in name and "contains 0 line" in nikto_string: continue 
            if "Insecure Session" in name and not any(sc in nikto_string for sc in SENSITIVE_COOKIES): continue 
            filtered_attacks.append(attack)

    # --- 🛡️ AUTONOMOUS SCORING MATRIX ---
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NOTE": 0}
    potential_deductions = 0
    counted_vulns = set()
    
    # 3. Dynamic Legacy Detection
    is_legacy_stack = False
    oldest_cve_year = 2026

    # Process Real-World CVEs with CVSS Awareness
    if cve_data:
        for item in cve_data:
            for cve_entry in item.get('cve', []):
                cve_id = cve_entry.split(':')[0].strip() if ':' in cve_entry else cve_entry
                
                match = re.search(r'CVE-(\d{4})-', cve_id.upper())
                if match:
                    cve_year = int(match.group(1))
                    if cve_year < oldest_cve_year: oldest_cve_year = cve_year
                    if cve_year <= 2019:
                        is_legacy_stack = True

                if cve_id not in counted_vulns:
                    if "[POTENTIAL]" in cve_entry.upper(): 
                        potential_deductions += 2
                    else:
                        # 🚀 UPGRADE: Use CVSS score for severity counting
                        score_match = re.search(r'CVSS: (\d+\.\d+)', cve_entry)
                        if score_match:
                            val = float(score_match.group(1))
                            if val >= 9.0: severity_counts["CRITICAL"] += 1
                            elif val >= 7.0: severity_counts["HIGH"] += 1
                            elif val >= 4.0: severity_counts["MEDIUM"] += 1
                            else: severity_counts["LOW"] += 1
                        else:
                            # Fallback to string matching if no CVSS found
                            for sev in severity_counts.keys():
                                if f"[{sev}" in cve_entry.upper(): severity_counts[sev] += 1
                    counted_vulns.add(cve_id)
    
    # Process Active Attacks
    has_insecure_session = False
    has_injection_risk = False

    if filtered_attacks:
        for attack in filtered_attacks:
            attack_key = f"{attack.get('Attack')}"
            sev = attack.get('Severity', 'LOW').upper()
            if attack_key not in counted_vulns:
                if sev in severity_counts: severity_counts[sev] += 1
                counted_vulns.add(attack_key)
            if "Session" in attack_key or "Cookie" in attack_key: has_insecure_session = True
            if any(x in attack_key for x in ["SQL Injection", "XSS", "CSP"]): has_injection_risk = True

    # --- 🚀 THE DYNAMIC MULTIPLIERS ---
    chaining_penalty = 0
    if has_insecure_session and has_injection_risk:
        chaining_penalty = 0 if is_high_value else 20 

    cms_penalty = 2 if any("CMS Architecture Detected" in k for k in counted_vulns) else 0
    stack_penalty = 20 if is_legacy_stack else 0

    method_penalty = 0
    if "access-control-allow-origin: *" in nikto_string: method_penalty += 15
    if "trace" in nikto_string: method_penalty += 15 
    if "put" in nikto_string or "delete" in nikto_string: method_penalty += 10 
    if "jsessionid" in nikto_string and "httponly" in nikto_string:
        method_penalty += 25 if is_high_value else 15 

    low_weight = 2 if is_waf_protected else 5
    residual_uncertainty = 3 

    # 🧮 FINAL AUTONOMOUS CALCULATION
    deductions = (severity_counts["CRITICAL"] * 45) + \
                 (severity_counts["HIGH"] * 30) + \
                 (severity_counts["MEDIUM"] * 15) + \
                 (severity_counts["LOW"] * low_weight) + \
                 (severity_counts["NOTE"] * 1) + \
                 potential_deductions + chaining_penalty + cms_penalty + \
                 stack_penalty + method_penalty + residual_uncertainty

    security_score = max(0, 100 - deductions)

    if security_score < 40: risk_level = "CRITICAL"
    elif security_score < 65: risk_level = "HIGH"
    elif security_score < 85: risk_level = "MEDIUM"
    else: risk_level = "LOW"

    # --- 📝 STORY BUILDING ---
    score_color = colors.red if security_score < 65 else colors.orange if security_score < 85 else colors.green
    score_style = ParagraphStyle('ScoreStyle', parent=styles['Heading1'], fontSize=26, textColor=score_color, alignment=1, spaceAfter=20)
    
    story = []
    story.append(Paragraph(f"Vulnerability Assessment Report: {target}", styles['Title']))
    story.append(Spacer(1, 10))
    story.append(Paragraph(f"SECURITY SCORE: {security_score}/100", score_style))
    story.append(Paragraph(f"OVERALL RISK LEVEL: {risk_level.upper()}", styles['Normal']))
    
    if is_high_value:
        story.append(Paragraph("<b>🛡️ HIGH-VALUE TARGET:</b> Application architecture indicates stateful authentication or sensitive data. Scoring strictness amplified.", ParagraphStyle('Info', parent=styles['Normal'], textColor=colors.blue)))
    if stack_penalty > 0:
        story.append(Paragraph(f"<b>⚠️ STACK OBSOLESCENCE:</b> Intelligence mapping found legacy vulnerabilities dating back to {oldest_cve_year}. Operating EOL software carries massive inherent risk.", ParagraphStyle('Warn', parent=styles['Normal'], textColor=colors.red)))
    if chaining_penalty > 0:
        story.append(Paragraph("<b>⚠️ EXPLOIT CHAIN DETECTED:</b> Vulnerabilities found that can be combined to escalate privileges or steal sessions.", ParagraphStyle('Warn', parent=styles['Normal'], textColor=colors.red)))
    if residual_uncertainty > 0 and security_score >= 90:
        story.append(Paragraph("<i>*Score capped at 97 due to professional residual uncertainty.</i>", styles['Normal']))
        
    story.append(Spacer(1, 12))

    # 1. Nmap Table
    story.append(Paragraph("1. Network Scan Results (Nmap)", styles['Heading2']))
    table_data = [['Port', 'State', 'Service', 'Version', 'Evidence']]
    for item in nmap_data:
        scripts = item.get('scripts', [])
        evidence = "<br/>".join([f"<b>{s['id']}:</b> {s['output'][:50]}..." for s in scripts]) if scripts else "None"
        table_data.append([str(item.get('port', '')), item.get('state', 'unknown').upper(), item.get('name', ''), item.get('version', ''), Paragraph(evidence, styles['Normal'])])
    
    table = Table(table_data, colWidths=[40, 50, 70, 90, 200])
    table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.grey), ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke), ('VALIGN', (0, 0), (-1, -1), 'TOP'), ('GRID', (0, 0), (-1, -1), 1, colors.black)]))
    story.append(table)

    # 2. Nikto Results
    story.append(Spacer(1, 20))
    story.append(Paragraph("2. Web Vulnerability Results (Nikto)", styles['Heading2']))
    nikto_clean = str(nikto_data).replace('\n', '<br/>')[:4000] 
    story.append(Paragraph(nikto_clean, styles['Code']))

    # 3. Endpoints
    story.append(Spacer(1, 20))
    story.append(Paragraph("3. Crawled & Fuzzed Endpoints", styles['Heading2']))
    for url in (crawled_urls or ["No endpoints found"]):
        story.append(Paragraph(f"- {url}", styles['Normal']))

    # 4. CVE Intelligence (Updated with CVSS Colors & Confidence Styles)
    story.append(Spacer(1, 20))
    story.append(Paragraph("4. Vulnerability Intelligence (CVE Mapping)", styles['Heading2']))
    if not cve_data:
        story.append(Paragraph("No relevant CVEs identified.", styles['Normal']))
    else:
        for item in cve_data:
            story.append(Paragraph(f"<b>{item['vuln']}</b>", styles['Normal']))
            for cve in item['cve']:
                # Dynamic Color Coding based on CVSS
                cve_color = colors.black
                if "[CVSS: 9." in cve or "[CVSS: 10." in cve: cve_color = colors.red
                elif "[CVSS: 7." in cve or "[CVSS: 8." in cve: cve_color = colors.orange
                
                # Style adjustment for Confidence levels
                cve_style = styles['Normal']
                if "(Confidence: LOW)" in cve:
                    cve_style = ParagraphStyle('LowConf', parent=styles['Normal'], fontName='Helvetica-Oblique')

                story.append(Paragraph(f"- {cve}", ParagraphStyle('CVEStyle', parent=cve_style, textColor=cve_color)))

    # 5. Attack Possibilities
    story.append(Spacer(1, 20))
    story.append(Paragraph("5. Attack Possibilities & Mitigation", styles['Heading2']))
    if not filtered_attacks:
        story.append(Paragraph("No active attack vectors validated by fuzzer.", styles['Normal']))
    else:
        for item in filtered_attacks:
            sev = item.get('Severity', 'LOW')
            story.append(Paragraph(f"<b>[{sev}] Attack:</b> {item.get('Attack', 'Unknown')}", styles['Normal']))
            if item.get('Evidence'):
                story.append(Paragraph(f"<i>Evidence: {item.get('Evidence')}</i>", styles['Normal']))
            story.append(Paragraph(f"<b>Mitigation:</b> {item.get('Mitigation', 'Unknown')}", styles['Normal']))
            story.append(Spacer(1, 10))

    doc.build(story)
    return path