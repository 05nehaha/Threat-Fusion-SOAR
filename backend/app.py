from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import json
import re

from database import init_db, get_db_connection
from scanner import run_nmap_scan, run_nikto_scan
from reporter import generate_pdf_report
from crawler import crawl_website
from cve_mapper import fetch_cves_dynamically
from visual_reporter import generate_visual_report

app = Flask(__name__)
CORS(app)

init_db()

REPORT_DIR = os.path.join(os.path.dirname(__file__), 'scans', 'reports')
if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

# =====================================================
# 🔥 DYNAMIC ATTACK → MITIGATION LOGIC MAP
# =====================================================
ATTACK_MAPPING = {
    "Missing Security Headers": {
        "Attack": "Clickjacking / Cross-Site Scripting (XSS)",
        "Mitigation": "Implement X-Frame-Options and Content-Security-Policy headers."
    },
    "Insecure Cookies": {
        "Attack": "Session Hijacking / Cookie Theft",
        "Mitigation": "Set HttpOnly and Secure flags on all sensitive cookies."
    },
    "Cross-Site Scripting (XSS)": {
        "Attack": "Client-side Script Injection",
        "Mitigation": "Sanitize all user inputs and use output encoding."
    },
    "Information Disclosure": {
        "Attack": "Data Leaks / Reconnaissance",
        "Mitigation": "Restrict access to sensitive directories (like .git or /admin) and disable directory listing."
    }
}

def threat_fusion_engine(nmap_data, nikto_data):
    risk_score = "LOW"
    findings_count = 0
    critical_indicators = ["PHP/5.6", "XSS", "Vulnerable", "wildcard", "X-Frame-Options"]
    combined_results = str(nmap_data) + nikto_data

    for indicator in critical_indicators:
        if indicator.lower() in combined_results.lower():
            risk_score = "HIGH"
            findings_count += 1

    siem_log = {
        "event_type": "vulnerability_scan",
        "risk_level": risk_score,
        "threat_indicators_found": findings_count,
        "raw_summary": combined_results[:500]
    }
    return risk_score, siem_log

def analyze_vulnerabilities(nikto_output, nmap_output):
    vulnerabilities = []
    nikto = nikto_output.lower()

    if "x-frame-options header is not present" in nikto or "content-security-policy header is not present" in nikto:
        vulnerabilities.append("Missing Security Headers")

    if "created without the httponly flag" in nikto:
        vulnerabilities.append("Insecure Cookies")

    if "xss" in nikto and "no xss" not in nikto:
        vulnerabilities.append("Cross-Site Scripting (XSS)")
    
    # Dynamic check for path exposures
    if "redirects (301)" in nikto and any(path in nikto for path in ["/admin", "/.git", "/config", "/.env"]):
        vulnerabilities.append("Information Disclosure")

    return list(set(vulnerabilities))

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target')

    if not target:
        return jsonify({"error": "No target provided"}), 400

    errors = []
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO scans (target, status) VALUES (?, ?)', (target, 'Running'))
    scan_id = cursor.lastrowid
    conn.commit()

    # 1. Nmap Scan
    try:
        nmap_results = run_nmap_scan(target)
    except Exception as e:
        errors.append(f"Nmap failed: {str(e)}")
        nmap_results = []

    # 2. Nikto Scan
    try:
        nikto_results = run_nikto_scan(target)
    except Exception:
        nikto_results = ""
        errors.append("Nikto scan blocked or unavailable")

    # 3. Crawler
    try:
        crawled_urls = crawl_website(target)
    except Exception:
        crawled_urls = []
        errors.append("Crawler blocked or site unreachable")

    # =====================================================
    # 🧠 INTELLIGENCE FUSION: NIKTO SERVER BANNER
    # =====================================================
    nikto_product = ""
    nikto_version = ""
    
    for line in nikto_results.split("\n"):
        if "+ Server:" in line and "No banner retrieved" not in line:
            raw_banner = line.split(":", 1)[1].strip()
            # FIX: Split "nginx/1.19.0" into "nginx" and "1.19.0"
            if '/' in raw_banner:
                parts = raw_banner.split('/')
                nikto_product = parts[0]
                nikto_version = parts[1].split(' ')[0] # Clean version
            else:
                nikto_product = raw_banner.split(' ')[0]
            break

    # =====================================================
    # 🔥 DYNAMIC CVE MAPPING (INTELLIGENT FALLBACK)
    # =====================================================
    final_cve_list = []
    searched_queries = set()
    identities = []

    # Gather data from Nmap
    for service in nmap_results:
        if service.get('state') == 'open':
            product = service.get('product', '').strip()
            name = service.get('name', '').strip()
            version = service.get('version', '').strip()
            
            # 🚨 THE FIX: Override generic "http" with Nikto's specific product
            if (not product or product.lower() == 'http') and nikto_product:
                product = nikto_product
                # If Nmap missed the version, use Nikto's version
                if not version:
                    version = nikto_version

            # If still just "http", we skip it (generic services have no CVEs)
            if product.lower() == 'http' and not version:
                continue

            identities.append({
                "product": product,
                "name": name, 
                "version": version,
                "cpe": service.get('cpe')
            })

    # FALLBACK: If Nmap found NOTHING but Nikto found a server
    if not identities and nikto_product:
         identities.append({
             "product": nikto_product, 
             "name": "", 
             "version": nikto_version, 
             "cpe": None
         })

    for iden in identities:
        prod = iden['product'] or iden['name']
        ver = iden['version']
        
        search_query = f"{prod} {ver}".strip()
        
        if not search_query or search_query in searched_queries:
            continue

        searched_queries.add(search_query)
        print(f"[*] Dynamically mapping CVEs for: {search_query}")

        found_cves = fetch_cves_dynamically(
            product=prod,
            version=ver,
            cpe=iden['cpe']
        )

        if found_cves:
            # --- UPDATED FORMATTING LOGIC FOR CVSS ---
            formatted_cves = []
            for c in found_cves[:5]:
                # Extract score and severity safely
                severity = c.get('severity', 'UNKNOWN')
                score = c.get('score', 'N/A')
                
                # Format: "[CRITICAL 9.8] CVE-2021-1234: Description..."
                severity_label = f"[{severity} {score}]"
                entry = f"{severity_label} {c['cve_id']}: {c['description'][:150]}..."
                formatted_cves.append(entry)

            final_cve_list.append({
                "vuln": f"Vulnerabilities in {search_query}",
                "cve": formatted_cves
            })

    # =====================================================
    # 🔁 DYNAMIC ATTACK GENERATION
    # =====================================================
    detected_vulns = analyze_vulnerabilities(nikto_results, nmap_results)

    dynamic_attacks = []
    for vuln in detected_vulns:
        if vuln in ATTACK_MAPPING:
            dynamic_attacks.append(ATTACK_MAPPING[vuln])

    # SIEM LOGS & RISK
    risk_level, siem_json = threat_fusion_engine(nmap_results, nikto_results)
    json_log_name = f"siem_log_{scan_id}.json"
    with open(os.path.join(REPORT_DIR, json_log_name), 'w') as f:
        json.dump(siem_json, f, indent=4)

    report_name = f"report_{scan_id}.pdf"

    # =====================================================
    # 📄 GENERATE FINAL REPORT
    # =====================================================
    try:
        generate_pdf_report(
            target,
            nmap_results,
            nikto_results,
            report_name,
            detected_vulns,
            dynamic_attacks, 
            final_cve_list,
            crawled_urls
        )
    except Exception as e:
        print(f"Report Error: {e}")
        errors.append("Report generation failed")

    # --- 📊 VISUAL REPORT GENERATION ---
    visual_report_name = f"visual_report_{scan_id}.pdf"
    try:
        generate_visual_report(
            scan_id,
            nmap_results,
            detected_vulns,
            final_cve_list,
            os.path.join(REPORT_DIR, visual_report_name)
        )
    except Exception as e:
        print(f"Visual Report Error: {e}")
        # Don't fail the scan if visuals fail

    # Update Database
    cursor.execute("""
        UPDATE scans
        SET status = ?, nmap_output = ?, nikto_output = ?, pdf_path = ?, risk_level = ?
        WHERE id = ?
    """, ("Completed", str(nmap_results), nikto_results, report_name, risk_level, scan_id))

    conn.commit()
    conn.close()

    return jsonify({
        "message": "Scan completed",
        "scan_id": scan_id,
        "pdf": report_name,
        "risk": risk_level,
        "warnings": errors
    })

@app.route('/api/history', methods=['GET'])
def get_history():
    conn = get_db_connection()
    scans = conn.execute('SELECT * FROM scans ORDER BY created_at DESC').fetchall()
    conn.close()
    return jsonify([dict(row) for row in scans])

@app.route('/api/download/<filename>', methods=['GET'])
def download_report(filename):
    return send_from_directory(REPORT_DIR, filename)

# --- 🗑️ NEW: CLEAR HISTORY ROUTE ---
@app.route('/api/clear_history', methods=['DELETE'])
def clear_history():
    try:
        conn = get_db_connection()
        conn.execute('DELETE FROM scans') # <--- This command deletes all rows
        conn.commit()
        conn.close()
        return jsonify({"message": "History cleared"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)