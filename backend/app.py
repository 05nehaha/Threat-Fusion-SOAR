from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
from dotenv import load_dotenv
load_dotenv() 
import json
import re  # 🚀 ADDED: Required for dynamic CVE year parsing
import hashlib

from database import init_db, get_db_connection
from scanner import run_nmap_scan, run_nikto_scan, check_web_vulnerabilities
from reporter import generate_pdf_report
from cve_mapper import fetch_cves_dynamically
from visual_reporter import generate_visual_report

app = Flask(__name__)
CORS(app)

# Initialize database on startup
init_db()

# Ensure the report directory exists
REPORT_DIR = os.path.join(os.path.dirname(__file__), 'scans', 'reports')
if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

# =====================================================
# 🛡️ INTEGRITY HASHING ENGINE
# =====================================================

def calculate_pdf_hash(filepath):
    """Generates a SHA-256 digital fingerprint for the report."""
    sha256_hash = hashlib.sha256()
    try:
        if os.path.exists(filepath):
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        return "FILE_NOT_FOUND"
    except Exception:
        return "HASH_ERROR"

# =====================================================
# 🚀 CORE SCANNING ROUTE
# =====================================================

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target', '').strip()

    if not target:
        return jsonify({"error": "No target provided"}), 400

    # Initialize Scan record in the Database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO scans (target, status) VALUES (?, ?)', (target, 'Running'))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()

    errors = []

    # --- 1. RUN NETWORK SCANNERS ---
    try:
        nmap_results = run_nmap_scan(target)
    except Exception as e:
        nmap_results = []
        errors.append(f"Nmap failed: {str(e)}")

    try:
        nikto_results = run_nikto_scan(target)
    except Exception:
        nikto_results = ""
        errors.append("Nikto scan timed out or was blocked")

    # --- 2. RUN OFFENSIVE ENGINE (Synchronized with scanner.py) ---
    try:
        # Capture BOTH findings and URLs
        detected_attacks, crawled_urls = check_web_vulnerabilities(target)
        if not crawled_urls:
            crawled_urls = [target]
    except Exception as e:
        print(f"[!] Deep Scan Error: {e}")
        detected_attacks = []
        crawled_urls = [target]

    # --- 3. INTELLIGENCE FUSION (Autonomous CVE Mapping) ---
    final_cve_list = []
    legacy_cve_count = 0
    processed_fingerprints = set()

    for service in nmap_results:
        if service.get('state') == 'open':
            prod_raw = service.get('product') or service.get('name', '')
            prod_clean = prod_raw.split(' ')[0].split('/')[0].lower().strip()
            ver_clean = service.get('version', '').strip()
            fingerprint = f"{prod_clean}-{ver_clean}"

            if ver_clean and fingerprint not in processed_fingerprints:
                found_cves = fetch_cves_dynamically(
                    product=prod_raw, 
                    version=ver_clean, 
                    cpe=service.get('cpe'),
                    service_context=nikto_results 
                )
                
                if found_cves:
                    # 🚀 UPGRADE: Filtering for modern CVEs (2016-2026)
                    modern = [c for c in found_cves if any(yr in c['cve_id'] for yr in [str(y) for y in range(2016, 2027)])]
                    legacy_cve_count += (len(found_cves) - len(modern))
                    
                    if modern:
                        # 🚀 EDIT HERE: Formatting to include CVSS Score and Forensic Confidence
                        formatted = [
                            f"{c.get('cve_id')} [CVSS: {c.get('score', 'N/A')}] (Confidence: {c.get('confidence')}): {c.get('description', '')[:100]}..." 
                            for c in modern[:5]
                        ]
                        
                        # Use the new label to signify unverified version mapping
                        final_cve_list.append({
                            "vuln": f"Intelligence-Mapped CVEs for {prod_raw} {ver_clean}", 
                            "cve": formatted
                        })
                processed_fingerprints.add(fingerprint)

    if legacy_cve_count > 0:
        final_cve_list.append({"vuln": "Legacy Vulnerability Intelligence", "cve": [f"⚠️ NOTICE: Filtered {legacy_cve_count} legacy vulnerabilities."]})

    # --- 4. DYNAMIC RISK DETERMINATION (Synchronized with Autonomous Engine) ---
    nikto_str = str(nikto_results).lower()
    has_crit = any(a.get('Severity') == 'CRITICAL' for a in detected_attacks)
    has_high = any(a.get('Severity') == 'HIGH' for a in detected_attacks)
    
    # 🚀 UPGRADE: Autonomous UI Sync for Protocol/API Risks
    if "jsessionid" in nikto_str and "httponly" in nikto_str: has_high = True
    if "trace" in nikto_str or "access-control-allow-origin: *" in nikto_str: has_high = True
    
    # Check for legacy CVEs dynamically
    for item in final_cve_list:
        for cve in item.get('cve', []):
            if "[CRITICAL]" in cve.upper(): has_crit = True
            if "[HIGH]" in cve.upper(): has_high = True
            # Auto-flag HIGH risk for unmaintained software (CVEs <= 2019)
            match = re.search(r'CVE-(\d{4})-', cve.upper())
            if match and int(match.group(1)) <= 2019: has_high = True 

    risk_level = "LOW"
    if has_crit: risk_level = "CRITICAL"
    elif has_high: risk_level = "HIGH"
    elif any(a.get('Severity') == 'MEDIUM' for a in detected_attacks): risk_level = "MEDIUM"

    # --- 5. GENERATE REPORTS ---
    report_name = f"report_{scan_id}.pdf"
    visual_report_name = f"visual_report_{scan_id}.pdf"
    visual_pdf_path = os.path.join(REPORT_DIR, visual_report_name)

    try:
        generate_pdf_report(
            target, nmap_results, nikto_results, report_name, 
            [], detected_attacks, final_cve_list, crawled_urls
        )
    except Exception as e:
        print(f"[!] PDF Report Error: {e}")
        errors.append("Standard PDF generation failed")

    try:
        # 🚀 UPGRADE: Passed crawled_urls to sync Visual Dashboard logic
        generate_visual_report(
            scan_id, nmap_results, detected_attacks, final_cve_list, 
            visual_pdf_path, nikto_results, crawled_urls
        )
    except Exception as e:
        print(f"[!] Visual Dashboard Error: {e}")

    # --- 6. INTEGRITY & DATABASE FINAL UPDATE ---
    full_report_path = os.path.join(REPORT_DIR, report_name)
    file_integrity_hash = calculate_pdf_hash(full_report_path)
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE scans
        SET status = ?, nmap_output = ?, nikto_output = ?, pdf_path = ?, risk_level = ?, file_hash = ?
        WHERE id = ?
    """, ("Completed", str(nmap_results), nikto_results, report_name, risk_level, file_integrity_hash, scan_id))

    conn.commit()
    conn.close()

    return jsonify({
        "message": "Scan cycle finished", 
        "scan_id": scan_id, 
        "risk": risk_level,
        "hash": file_integrity_hash,
        "errors": errors
    })

# =====================================================
# 📁 HISTORY & UTILITY ROUTES
# =====================================================

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