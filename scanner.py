import nmap
import subprocess
import os
import signal
import requests
import time
import re
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
import ipaddress
import urllib3
import warnings
from bs4 import XMLParsedAsHTMLWarning

# --- 🔇 SILENCE NOISE ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# --- 🧠 ENHANCED THREAT CATALOG ---
THREAT_CATALOG = {
    "SQLI": {"Attack": "SQL Injection (Database Exposure)", "Mitigation": "Use parameterized queries.", "Severity": "CRITICAL"},
    "BLIND_SQLI": {"Attack": "Blind SQL Injection (Time-Based)", "Mitigation": "Use prepared statements. Disable stacked queries.", "Severity": "CRITICAL"},
    "XSS": {"Attack": "Reflected Cross-Site Scripting (XSS)", "Mitigation": "Implement context-aware output encoding.", "Severity": "HIGH"},
    "MISSING_CSP": {"Attack": "Missing Content-Security-Policy (CSP)", "Mitigation": "Implement a strict CSP header.", "Severity": "NOTE"},
    "CLICKJACKING": {"Attack": "Missing Anti-Clickjacking Protection", "Mitigation": "Implement DENY or SAMEORIGIN X-Frame-Options.", "Severity": "LOW"},
    "INSECURE_COOKIE": {"Attack": "Insecure Session Management", "Mitigation": "Sensitive cookies missing HttpOnly/Secure flags.", "Severity": "MEDIUM"}
}

# Forensic Validation Payloads
FUZZ_PAYLOADS = {
    "SQLI_ERROR": ["'", "''", "1' OR '1'='1", "admin' --", "' OR 1=1#"],
    "SQLI_TIME": ["1' OR SLEEP(3)--", "1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", "1'; WAITFOR DELAY '0:0:3'--"],
    "XSS": ["<script>alert(1)</script>", "><img src=x onerror=alert(1)>"]
}

CMS_SIGNATURES = {
    "WordPress": ['href="/wp-content/', 'src="/wp-includes/', 'rel="https://api.w.org/"', '<meta name="generator" content="WordPress"'],
    "Joomla": ['<meta name="generator" content="Joomla!', 'href="/components/com_'],
    "Drupal": ['<meta name="Generator" content="Drupal', 'src="/sites/default/files/']
}

SENSITIVE_KEYWORDS = ["index of /", "fatal error:", "stack trace:", "db_password", "sql syntax", "root:x:0:0:", "ora-01756", "mysql_fetch"]

def is_valid_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def run_nmap_scan(target):
    parsed = urlparse(target)
    clean_target = parsed.netloc if parsed.netloc else target
    if ":" in clean_target and not is_valid_ip(clean_target):
        clean_target = clean_target.split(":")[0]

    nm = nmap.PortScanner()
    nmap_args = os.getenv("NMAP_ARGS", "-sV --version-light -Pn -n --script http-title,ssl-cert -T4 --min-rate 500")
    try:
        print(f"[*] Starting Evidence-Based Nmap Scan on: {clean_target}")
        nm.scan(clean_target, arguments=nmap_args)
    except Exception:
        return []

    scan_results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                service = nm[host][proto][port]
                scripts = service.get('script', {})
                formatted_scripts = [{"id": sid, "output": out.strip()} for sid, out in scripts.items()]
                scan_results.append({
                    "port": port, "name": service.get('name', 'unknown'),
                    "product": service.get('product', ''), "version": service.get('version', ''),
                    "state": service.get('state', ''), "scripts": formatted_scripts
                })
    return scan_results

def check_web_vulnerabilities(target_url):
    print(f"[*] Starting OFFENSIVE Validation Engine on: {target_url}")
    detected = []
    seen_urls = set()
    vulnerable_signatures = set() 
    
    # 🚀 Logic State: Tracks CDN presence dynamically to avoid speculating on network lag
    GLOBAL_STATE = {"csp_reported": False, "clickjacking_reported": False, "is_cdn": False}
    
    target_domain = urlparse(target_url).netloc or target_url
    SENSITIVE_COOKIES = ["jsessionid", "phpsessid", "aspsessionid", "auth_token", "wordpress_logged_in", "session", "token", "__cf_bm"]
    
    if not target_url.startswith(("http://", "https://")):
         target_url = "http://" + target_url

    def perform_fuzzing(url, params):
        for param in params:
            for p_type, payloads in FUZZ_PAYLOADS.items():
                for payload in payloads:
                    test_params = params.copy()
                    test_params[param] = payload
                    try:
                        # Baseline establishing using dynamic allow_redirects
                        b_start = time.time()
                        requests.get(url, params=params, timeout=5, verify=False, allow_redirects=True)
                        baseline_time = time.time() - b_start

                        # Attack Request
                        start_time = time.time()
                        res = requests.get(url, params=test_params, timeout=10, verify=False, allow_redirects=True)
                        elapsed_time = time.time() - start_time

                        # 1. Error-Based SQLi
                        if p_type == "SQLI_ERROR" and any(err in res.text.lower() for err in ["sql syntax", "mysql_fetch", "ora-01756"]):
                            sig = f"SQLI-ERR-{url}-{param}"
                            if sig not in vulnerable_signatures:
                                vuln = THREAT_CATALOG["SQLI"].copy()
                                vuln["Evidence"] = f"Database error detected in GET param '{param}'."
                                detected.append(vuln)
                                vulnerable_signatures.add(sig)
                        
                        # 2. 🛡️ Infrastructure-Aware SQLi Guard
                        elif p_type == "SQLI_TIME":
                            # If target uses global infra (GWS, Cloudflare), latency is likely network-bound
                            if GLOBAL_STATE["is_cdn"]: continue
                            
                            delta = elapsed_time - baseline_time
                            if delta >= 3.0:
                                sig = f"SQLI-TIME-{url}-{param}"
                                if sig not in vulnerable_signatures:
                                    detected.append({
                                        "Attack": f"[POTENTIAL] Time-Based SQL Injection",
                                        "Mitigation": "Verify server latency. Use prepared statements.",
                                        "Severity": "MEDIUM", 
                                        "Evidence": f"Confirmed Delay: {elapsed_time:.2f}s (Baseline: {baseline_time:.2f}s)."
                                    })
                                    vulnerable_signatures.add(sig)
                    except: pass

    def crawl_and_test(url, depth=0):
        if depth > 1 or url in seen_urls: return
        seen_urls.add(url)
        try:
            browser_headers = {'User-Agent': 'SecurityValidator/7.0 (Forensic Engine)'}
            # 🚀 Redirect-Aware: Follows all jumps to reach the secure final destination
            response = requests.get(url, timeout=5, headers=browser_headers, verify=False, allow_redirects=True)
            
            final_headers = response.headers
            html_content = response.text
            soup = BeautifulSoup(html_content, 'html.parser')

            # --- 🛡️ Infrastructure Fingerprinting ---
            server_banner = final_headers.get('Server', '').lower()
            if any(cdn in server_banner for cdn in ["gws", "sffe", "cloudflare", "akamai", "imperva"]):
                GLOBAL_STATE["is_cdn"] = True

            # --- 🛡️ Header Validation (Final Destination Only) ---
            csp = final_headers.get('Content-Security-Policy') or final_headers.get('Content-Security-Policy-Report-Only')
            if not csp and not GLOBAL_STATE["csp_reported"]:
                detected.append(THREAT_CATALOG["MISSING_CSP"])
                GLOBAL_STATE["csp_reported"] = True

            xfo = final_headers.get('X-Frame-Options')
            # Check for XFO or the modern frame-ancestors CSP equivalent
            if not xfo and "frame-ancestors" not in str(csp).lower() and not GLOBAL_STATE["clickjacking_reported"]:
                detected.append(THREAT_CATALOG["CLICKJACKING"])
                GLOBAL_STATE["clickjacking_reported"] = True

            # --- Dynamic Fuzzing ---
            parsed_url = urlparse(response.url)
            url_params = parse_qs(parsed_url.query)
            if url_params:
                perform_fuzzing(response.url.split('?')[0], {k: v[0] for k, v in url_params.items()})

            for link in soup.find_all(['a', 'link'], href=True):
                path = link.get('href')
                crawl_and_test(urljoin(response.url, path).split('#')[0], depth + 1)
        except: pass

    crawl_and_test(target_url)
    return detected, list(seen_urls)

def run_nikto_scan(target):
    print(f"[*] Starting Controlled Nikto scan on: {target}")
    try:
        cmd = ["nikto", "-h", target, "-Tuning", "123", "-maxtime", "600s", "-nointeractive"]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            stdout, stderr = p.communicate(timeout=610)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            stdout, stderr = p.communicate()
        return (stdout or "") + (f"\n[stderr]\n{stderr}" if stderr else "")
    except Exception as e:
        return f"Nikto failed: {str(e)}"