from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import json
import re
import hashlib

from database import init_db, get_db_connection
from scanner import run_nmap_scan, run_nikto_scan
from reporter import generate_pdf_report
from crawler import crawl_website
from cve_mapper import fetch_cves_dynamically
from visual_reporter import generate_visual_report

app = Flask(__name__)
CORS(app)

# Initialize the persistent local database
init_db()

# Ensure dedicated directories exist for storing PDF reports
REPORT_DIR = os.path.join(os.path.dirname(__file__), 'scans', 'reports')
if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

# =====================================================
# 🛡️ INTEGRITY HASHING ENGINE
# =====================================================

def calculate_pdf_hash(filepath):
    """Generates a SHA-256 digital fingerprint for forensic report integrity."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return "HASH_ERROR"

# =====================================================
# 🔥 ACTIONABLE INTELLIGENCE LOGIC MAP
# =====================================================

ATTACK_MAPPING = {
    "Outdated Software: PHP 5.x EOL": {
        "Attack": "Remote Code Execution (RCE) / Known Exploit Utilization",
        "Mitigation": "Upgrade to a supported version of PHP (8.2+). Legacy versions do not receive security patches.",
        "Weight": 25
    },
    "Insecure Cross-Domain Policy": {
        "Attack": "Cross-Site Request Forgery (CSRF) / Data Theft",
        "Mitigation": "Replace full wildcard '*' entries in crossdomain.xml or clientaccesspolicy.xml with specific, trusted domain origins.",
        "Weight": 15
    },
    "Missing Security Header: X-Frame-Options": {
        "Attack": "Clickjacking Vulnerability",
        "Mitigation": "Implement X-Frame-Options: SAMEORIGIN or DENY in your web server configuration.",
        "Weight": 5
    },
    "Missing Security Header: CSP": {
        "Attack": "Cross-Site Scripting (XSS) / Data Injection",
        "Mitigation": "Implement a strict Content-Security-Policy (CSP) to restrict untrusted script execution.",
        "Weight": 10
    },
    "Insecure Cookies": {
        "Attack": "Session Hijacking / Cookie Theft",
        "Mitigation": "Set HttpOnly and Secure flags on all sensitive session cookies.",
        "Weight": 5
    },
    "Cross-Site Scripting (XSS)": {
        "Attack": "Client-side Script Injection",
        "Mitigation": "Sanitize all user inputs and use context-aware output encoding.",
        "Weight": 20
    },
    "Information Disclosure": {
        "Attack": "Data Leaks / Reconnaissance",
        "Mitigation": "Restrict access to sensitive directories (like .git or /admin) and ensure 404s are handled correctly.",
        "Weight": 10
    }
}

# =====================================================
# 🚀 DYNAMIC RISK SCORING ENGINE (NORMALIZED)
# =====================================================

def threat_fusion_engine(nmap_data, nikto_data, vulnerabilities, final_cve_list, legacy_count=0):
    """Normalized Risk Model: Prevents score collapse on large-scale sites (like YouTube)."""
    score = 100
    max_cve_score = 0.0

    # 1. CVE IMPACT (Prioritized)
    for entry in final_cve_list:
        for cve_string in entry.get('cve', []):
            match = re.search(r"(\d+\.\d+)", cve_string)
            if match:
                val = float(match.group(1))
                max_cve_score = max(max_cve_score, val)
                
                # Deduct based on highest CVSS found
                if val >= 9.0: score -= 30
                elif val >= 7.0: score -= 20
                elif val >= 4.0: score -= 10

    # 2. HEURISTIC WEIGHTED IMPACT (Normalized)
    # We cap total header/cookie penalties to prevent "Death by 1000 cuts"
    header_penalty = 0
    for v in vulnerabilities:
        weight = ATTACK_MAPPING.get(v, {}).get("Weight", 5)
        if weight <= 10: # Header/Cookie issues
            header_penalty += weight
        else: # Structural issues like EOL PHP or XSS
            score -= weight
    
    score -= min(header_penalty, 20) # Cap header penalties at -20

    # 3. LEGACY DEBT (Normalized)
    legacy_penalty = min(legacy_count * 1, 10)
    score -= legacy_penalty
    
    score = max(0, min(100, score))

    # Dynamic Risk Level
    if score <= 40 or max_cve_score >= 9.0:
        risk_level = "CRITICAL"
    elif score <= 60 or max_cve_score >= 7.5:
        risk_level = "HIGH"
    elif score <= 85 or len(vulnerabilities) > 0:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return risk_level, {"security_score": int(score), "max_cve": max_cve_score}

# =====================================================
# 🧠 DYNAMIC HEURISTIC ANALYZER (REDIRECT SHIELD)
# =====================================================

def analyze_vulnerabilities(nikto_output, nmap_output):
    """Dynamic analysis: Filters out redirects and tracking cookies."""
    vulnerabilities = []
    nikto = nikto_output.lower()

    # 1. Outdated Software (Critical Version Match)
    if "php/5." in nikto:
        vulnerabilities.append("Outdated Software: PHP 5.x EOL")

    # 2. Wildcard Check
    if "full wildcard entry" in nikto:
        vulnerabilities.append("Insecure Cross-Domain Policy")

    # 3. Smart Header Detection
    if "x-frame-options header is not present" in nikto:
        vulnerabilities.append("Missing Security Header: X-Frame-Options")
    
    if "content-security-policy" not in nikto:
        vulnerabilities.append("Missing Security Header: CSP")

    # 4. Filtered Cookie Logic (Ignores CDN/Tracking cookies)
    ignore_cookies = ['__cf', '_ga', '_gid', 'nid', 'aec', 'test_cookie']
    if "httponly flag" in nikto:
        # Check if the reported insecure cookie is a tracking/CDN cookie
        found_insecure = False
        lines = nikto.split('\n')
        for line in lines:
            if "cookie" in line and "without the httponly flag" in line:
                if not any(c in line for c in ignore_cookies):
                    found_insecure = True
                    break
        if found_insecure:
            vulnerabilities.append("Insecure Cookies")

    # 5. Redirect Shield for Information Disclosure
    # Only flags paths if they actually exist (not a 301/302 redirect)
    sensitive_paths = ["/admin", "/.git", "/config", "/.env"]
    for path in sensitive_paths:
        if path in nikto:
            # Check if this specific path entry in Nikto mentions a redirect
            path_evidence = [line for line in nikto.split('\n') if path in line]
            is_redirect = any("redirects" in line or "(30" in line for line in path_evidence)
            if not is_redirect:
                vulnerabilities.append("Information Disclosure")

    # 6. Injection Points
    if any(x in nikto for x in ["xss", "cross-site scripting", "osvdb-2102"]):
        vulnerabilities.append("Cross-Site Scripting (XSS)")

    return list(set(vulnerabilities))

# =====================================================
# 🔎 INTEGRATED SCAN ROUTE
# =====================================================

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target')

    if not target:
        return jsonify({"error": "No target provided"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO scans (target, status) VALUES (?, ?)', (target, 'Running'))
    scan_id = cursor.lastrowid
    conn.commit()

    # 1. Intel Gathering
    try: nmap_results = run_nmap_scan(target)
    except Exception: nmap_results = []
    
    try: nikto_results = run_nikto_scan(target)
    except Exception: nikto_results = ""
    
    try: crawled_urls = crawl_website(target)
    except Exception: crawled_urls = []

    # 2. Service Fingerprinting
    nikto_product = ""
    nikto_version = ""
    for line in nikto_results.split("\n"):
        if "+ Server:" in line and "No banner retrieved" not in line:
            raw_banner = line.split(":", 1)[1].strip()
            if '/' in raw_banner:
                parts = raw_banner.split('/')
                nikto_product, nikto_version = parts[0], parts[1].split(' ')[0]
            else:
                nikto_product = raw_banner.split(' ')[0]
            break

    identities = []
    for service in nmap_results:
        if service.get('state') == 'open':
            prod, ver = service.get('product', '').strip(), service.get('version', '').strip()
            if (not prod or prod.lower() == 'http') and nikto_product:
                prod = nikto_product
                if not ver: ver = nikto_version
            identities.append({"product": prod, "name": service.get('name', ''), "version": ver, "cpe": service.get('cpe')})

    # 3. CVE Logic
    final_cve_list, legacy_cve_count, processed = [], 0, set()
    for iden in identities:
        prod, ver = iden['product'] or iden['name'], iden['version']
        if not prod or f"{prod}_{ver}" in processed: continue
        
        found_cves = fetch_cves_dynamically(product=prod, version=ver, cpe=iden['cpe'])
        if found_cves:
            processed.add(f"{prod}_{ver}")
            modern = [c for c in found_cves if any(year in c['cve_id'] for year in [str(y) for y in range(2016, 2027)])]
            legacy_cve_count += (len(found_cves) - len(modern))
            if modern:
                formatted = [f"[{c.get('severity', 'UNKNOWN')} {c.get('score', 'N/A')}] {c['cve_id']}: {c['description'][:150]}..." for c in modern[:5]]
                final_cve_list.append({"vuln": f"Modern Vulnerabilities in {prod} {ver}", "cve": formatted})

    if legacy_cve_count > 0:
        final_cve_list.append({"vuln": "Legacy Vulnerability Intelligence", "cve": [f"⚠️ NOTICE: Engine identified {legacy_cve_count} additional legacy vulnerabilities (pre-2016)."]})

    # 4. Final Processing
    detected_vulns = analyze_vulnerabilities(nikto_results, nmap_results)
    dynamic_attacks = [ATTACK_MAPPING[v] for v in detected_vulns if v in ATTACK_MAPPING]
    risk_level, siem_json = threat_fusion_engine(nmap_results, nikto_results, detected_vulns, final_cve_list, legacy_count=legacy_cve_count)
    
    report_name = f"report_{scan_id}.pdf"
    full_report_path = os.path.join(REPORT_DIR, report_name)
    
    try:
        generate_pdf_report(target, nmap_results, nikto_results, report_name, detected_vulns, dynamic_attacks, final_cve_list, crawled_urls, security_score=siem_json["security_score"], risk_level=risk_level)
    except Exception: pass

    try: 
        generate_visual_report(scan_id, nmap_results, detected_vulns, final_cve_list, os.path.join(REPORT_DIR, f"visual_report_{scan_id}.pdf"))
    except Exception: pass

    # 5. Finalize
    file_hash = calculate_pdf_hash(full_report_path)
    cursor.execute("""UPDATE scans SET status = ?, nmap_output = ?, nikto_output = ?, pdf_path = ?, risk_level = ?, file_hash = ?, security_score = ? WHERE id = ?""", 
                    ("Completed", str(nmap_results), nikto_results, report_name, risk_level, file_hash, siem_json["security_score"], scan_id))
    conn.commit()
    conn.close()

    return jsonify({"message": "Scan completed", "risk": risk_level, "hash": file_hash, "score": siem_json["security_score"]})

@app.route('/api/history', methods=['GET'])
def get_history():
    conn = get_db_connection()
    scans = conn.execute('SELECT * FROM scans ORDER BY created_at DESC').fetchall()
    conn.close()
    return jsonify([dict(row) for row in scans])

@app.route('/api/download/<filename>', methods=['GET'])
def download_report(filename):
    return send_from_directory(REPORT_DIR, filename)

@app.route('/api/clear_history', methods=['DELETE'])
def clear_history():
    try:
        conn = get_db_connection()
        conn.execute('DELETE FROM scans')
        conn.commit()
        conn.close()
        return jsonify({"message": "History cleared"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)