import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import os
import re

def generate_visual_report(scan_id, nmap_data, detected_vulns, final_cve_list, output_path, nikto_data="", crawled_urls=None):
    """
    Professional Dashboard: 100% synchronized with CVSS Intelligence and Forensic Engine.
    Renames 'NOTE' to 'INFO' for professional readability.
    """
    crawled_urls = crawled_urls or []
    nikto_string = str(nikto_data).lower()
    
    # --- 🧠 100% DYNAMIC BEHAVIORAL ENGINE ---
    is_waf_protected = any(waf in nikto_string for waf in ["cloudflare", "imperva", "akamai", "barracuda", "cloudfront"])

    is_high_value = False
    auth_indicators = ['login', 'signin', 'admin', 'dashboard', 'auth', 'account']
    if any(any(ind in url.lower() for ind in auth_indicators) for url in crawled_urls) or "session" in nikto_string or "token" in nikto_string:
        is_high_value = True

    filtered_attacks = []
    SENSITIVE_COOKIES = ["jsessionid", "phpsessid", "aspsessionid", "auth_token", "wordpress_logged_in", "session"]
    if detected_vulns:
        for attack in detected_vulns:
            name = attack.get('Attack', '')
            if "Clickjacking" in name and "x-frame-options: sameorigin" in nikto_string: continue 
            if "Cross-Domain Policy" in name and "contains 0 line" in nikto_string: continue 
            if "Insecure Session" in name and not any(sc in nikto_string for sc in SENSITIVE_COOKIES): continue 
            filtered_attacks.append(attack)

    # --- 🛡️ EXACT MATH SYNCHRONIZATION (CVSS AWARE) ---
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NOTE": 0}
    potential_deductions = 0
    counted_vulns = set()
    is_legacy_stack = False

    if final_cve_list:
        for item in final_cve_list:
            for cve_entry in item.get('cve', []):
                cve_id = cve_entry.split(':')[0].strip() if ':' in cve_entry else cve_entry
                
                # Check for legacy stack
                match = re.search(r'CVE-(\d{4})-', cve_id.upper())
                if match and int(match.group(1)) <= 2019:
                    is_legacy_stack = True

                if cve_id not in counted_vulns:
                    if "[POTENTIAL]" in cve_entry.upper(): 
                        potential_deductions += 2
                    else:
                        # 🚀 UPGRADE: Dashboard now uses CVSS scores for the Pie Chart distribution
                        score_match = re.search(r'CVSS: (\d+\.\d+)', cve_entry)
                        if score_match:
                            val = float(score_match.group(1))
                            if val >= 9.0: severity_counts["CRITICAL"] += 1
                            elif val >= 7.0: severity_counts["HIGH"] += 1
                            elif val >= 4.0: severity_counts["MEDIUM"] += 1
                            else: severity_counts["LOW"] += 1
                        else:
                            for sev in severity_counts.keys():
                                if f"[{sev}" in cve_entry.upper(): severity_counts[sev] += 1
                    counted_vulns.add(cve_id)

    has_insecure_session = False
    has_injection_risk = False
    attack_labels = []

    if filtered_attacks:
        for attack in filtered_attacks:
            attack_name = attack.get('Attack', 'Unknown Threat')
            attack_key = f"{attack_name}"
            sev = attack.get('Severity', 'LOW').upper()
            
            if attack_key not in counted_vulns:
                if sev in severity_counts: severity_counts[sev] += 1
                counted_vulns.add(attack_key)
                short_name = attack_name.split('(')[0].strip() if '(' in attack_name else attack_name
                
                display_sev = "INFO" if sev == "NOTE" else sev
                attack_labels.append(f"[{display_sev}] {short_name}")
            
            if "Session" in attack_key or "Cookie" in attack_key: has_insecure_session = True
            if any(x in attack_key for x in ["SQL Injection", "XSS", "CSP"]): has_injection_risk = True

    # 🚀 AUTONOMOUS PENALTIES (Synchronized with reporter.py)
    chaining_penalty = (0 if is_high_value else 10) if (has_insecure_session and has_injection_risk) else 0
    cms_penalty = 2 if any("CMS Architecture Detected" in k for k in counted_vulns) else 0
    stack_penalty = 20 if is_legacy_stack else 0
    residual_uncertainty = 3 
    
    method_penalty = 0
    if "access-control-allow-origin: *" in nikto_string: method_penalty += 15
    if "trace" in nikto_string: method_penalty += 15 
    if "put" in nikto_string or "delete" in nikto_string: method_penalty += 10 
    if "jsessionid" in nikto_string and "httponly" in nikto_string:
        method_penalty += 25 if is_high_value else 15 

    low_weight = 2 if is_waf_protected else 5
    
    deductions = (severity_counts["CRITICAL"] * 45) + (severity_counts["HIGH"] * 30) + \
                 (severity_counts["MEDIUM"] * 15) + (severity_counts["LOW"] * low_weight) + \
                 (severity_counts["NOTE"] * 1) + potential_deductions + chaining_penalty + \
                 cms_penalty + stack_penalty + method_penalty + residual_uncertainty

    security_score = max(0, 100 - deductions)

    # --- 📊 PREPARE CHART DATA ---
    severity_data = {("INFO" if k == "NOTE" else k): v for k, v in severity_counts.items() if v > 0}

    open_ports = []
    for s in nmap_data:
        if s.get('state') == 'open':
            open_ports.append(f"{s.get('port')}\n{s.get('name', 'unknown')}")

    unique_attack_labels = list(set(attack_labels))

    # --- 🎨 CREATE PDF DASHBOARD ---
    with PdfPages(output_path) as pdf:
        fig = plt.figure(figsize=(10, 14)) 
        fig.suptitle(f"SECURITY POSTURE DASHBOARD - SCAN #{scan_id}", fontsize=18, fontweight='bold', y=0.96)
        
        score_color = '#388e3c' if security_score >= 85 else '#fbc02d' if security_score >= 60 else '#d32f2f'
        fig.text(0.5, 0.92, f"OVERALL SECURITY SCORE: {security_score}/100", 
                  ha='center', fontsize=15, fontweight='bold', color=score_color, 
                  bbox=dict(facecolor='white', edgecolor=score_color, boxstyle='round,pad=0.5'))

        # CHART 1: SEVERITY (Pie)
        ax1 = plt.subplot(3, 1, 1)
        if severity_data:
            colors_map = {'CRITICAL': '#d32f2f', 'HIGH': '#f57c00', 'MEDIUM': '#fbc02d', 'LOW': '#388e3c', 'INFO': '#0288d1'}
            chart_colors = [colors_map.get(k, 'gray') for k in severity_data.keys()]
            ax1.pie(severity_data.values(), labels=severity_data.keys(), autopct='%1.1f%%', 
                    colors=chart_colors, startangle=140, pctdistance=0.85, explode=[0.05]*len(severity_data))
            ax1.set_title("Vulnerability Severity Distribution (CVSS Weighted)", fontsize=14, fontweight='bold', pad=15)
        else:
            ax1.text(0.5, 0.5, "No Severity Data Available", ha='center', fontsize=12, color='gray')
            ax1.axis('off')

        # CHART 2: PORTS (Vertical Bar)
        ax2 = plt.subplot(3, 1, 2)
        if open_ports:
            ax2.bar(open_ports, [1]*len(open_ports), color='#455a64', edgecolor='black', alpha=0.8)
            ax2.set_title("Open Ports & Services", fontsize=14, fontweight='bold', pad=15)
            ax2.set_yticks([]) 
            plt.xticks(fontsize=9, fontweight='medium') 
        else:
            ax2.text(0.5, 0.5, "No Open Ports Detected", ha='center', fontsize=12, color='gray')
            ax2.axis('off')

        # CHART 3: THREAT VECTORS (Horizontal Bar)
        ax3 = plt.subplot(3, 1, 3)
        if unique_attack_labels:
            sorted_attacks = sorted(unique_attack_labels)
            y_pos = range(len(sorted_attacks))
            ax3.barh(y_pos, [1]*len(sorted_attacks), color='#ef6c00', edgecolor='black', height=0.6)
            ax3.set_yticks(y_pos)
            ax3.set_yticklabels(sorted_attacks, fontsize=10)
            ax3.set_title("Forensic Threat Vectors", fontsize=14, fontweight='bold', pad=15)
            ax3.set_xticks([])
            ax3.invert_yaxis() 
        else:
            ax3.text(0.5, 0.5, "No Active Threats Detected", ha='center', fontsize=12, color='gray')
            ax3.axis('off')

        plt.subplots_adjust(hspace=0.5, top=0.85) 
        plt.tight_layout(rect=[0.05, 0.05, 0.95, 0.90]) 
        pdf.savefig(fig)
        plt.close()

    print(f"[*] Visual Report Synchronized: {output_path}")