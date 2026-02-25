from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import json # New: For SIEM JSON logging
from database import init_db, get_db_connection
from scanner import run_nmap_scan, run_nikto_scan
from reporter import generate_pdf_report

app = Flask(__name__)
CORS(app)

init_db()

REPORT_DIR = os.path.join(os.path.dirname(__file__), 'scans', 'reports')

def threat_fusion_engine(nmap_data, nikto_data):
    """
    This is the SOAR/SIEM logic layer. 
    It 'fuses' data and calculates a Risk Score automatically.
    """
    risk_score = "LOW"
    findings_count = 0
    
    # Logic: Search for 'High' risk indicators found in your reports
    # Example: PHP 5.6 or missing security headers [cite: 18, 20]
    critical_indicators = ['PHP/5.6', 'XSS', 'Vulnerable', 'wildcard', 'X-Frame-Options']
    
    combined_results = str(nmap_data) + nikto_data
    
    for indicator in critical_indicators:
        if indicator.lower() in combined_results.lower():
            risk_score = "HIGH"
            findings_count += 1

    # Structured Data for SIEM ingestion
    siem_log = {
        "event_type": "vulnerability_scan",
        "risk_level": risk_score,
        "threat_indicators_found": findings_count,
        "raw_summary": combined_results[:500] # Snippet for the SIEM
    }
    
    return risk_score, siem_log

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

    try:
        # 1. ORCHESTRATION: Running multiple tools automatically
        nmap_results = run_nmap_scan(target)
        nikto_results = run_nikto_scan(target)

        # 2. DATA FUSION: Analyzing the raw output for risk
        risk_level, siem_json = threat_fusion_engine(nmap_results, nikto_results)

        # 3. SIEM INTEGRATION: Saving structured JSON logs
        json_log_name = f"siem_log_{scan_id}.json"
        with open(os.path.join(REPORT_DIR, json_log_name), 'w') as f:
            json.dump(siem_json, f, indent=4)

        # 4. REPORTING: Generating the PDF human-readable report [cite: 8]
        report_name = f"report_{scan_id}.pdf"
        generate_pdf_report(target, nmap_results, nikto_results, report_name)

        # Update Database with Risk Level
        cursor.execute('''
            UPDATE scans 
            SET status = ?, nmap_output = ?, nikto_output = ?, pdf_path = ?, risk_level = ? 
            WHERE id = ?
        ''', ('Completed', str(nmap_results), nikto_results, report_name, risk_level, scan_id))
        conn.commit()

        return jsonify({
            "message": "Scan completed", 
            "scan_id": scan_id, 
            "pdf": report_name, 
            "risk": risk_level
        })

    except Exception as e:
        cursor.execute('UPDATE scans SET status = ? WHERE id = ?', ('Failed', scan_id))
        conn.commit()
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/history', methods=['GET'])
def get_history():
    conn = get_db_connection()
    scans = conn.execute('SELECT * FROM scans ORDER BY created_at DESC').fetchall()
    conn.close()
    return jsonify([dict(row) for row in scans])

@app.route('/api/download/<filename>', methods=['GET'])
def download_report(filename):
    return send_from_directory(REPORT_DIR, filename)

if __name__ == "__main__":
    app.run(debug=True, port=5000)