import requests
import time
import os

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_cves_dynamically(product=None, version=None, cpe=None, limit=5, service_context=""):
    """
    Precision engine with stack-aware filtering. 
    Prevents 'Groovy' or 'Java' CVEs from appearing on standard C-based stacks.
    """
    results = []
    
    noise = ["httpd", "server", "web", "software", "project"]
    product_clean = str(product).lower()
    for word in noise:
        product_clean = product_clean.replace(word, "").strip()
    
    version_clean = str(version).split(' ')[0].strip() if version else None

    # --- ATTEMPT 1: PRECISION SEARCH (CPE) ---
    if cpe:
        params = {"cpeName": cpe, "resultsPerPage": limit}
        results = call_nvd_api(params, service_context)
        if results: return results

    # --- ATTEMPT 2: EXACT KEYWORD SEARCH ---
    if product_clean and version_clean:
        exact_query = f"{product_clean} {version_clean}"
        params = {
            "keywordSearch": exact_query, 
            "keywordExactMatch": "", 
            "resultsPerPage": limit
        }
        results = call_nvd_api(params, service_context)
        if results: return results

    # --- ATTEMPT 3: LOOSE FALLBACK SEARCH ---
    if product_clean and version_clean:
        core_product = product_clean.split(' ')[0].strip() 
        loose_query = f"{core_product} {version_clean}"
        params = {
            "keywordSearch": loose_query,
            "resultsPerPage": limit
        }
        results = call_nvd_api(params, service_context)
        if results: return results

    return results

def call_nvd_api(params, service_context=""):
    """
    Handles API request with a Stack-Mismatch Gatekeeper and 
    adds Forensic Confidence weighting.
    """
    api_key = os.getenv("NVD_API_KEY")
    headers = {'User-Agent': 'VulnerabilityScanner/1.0', 'Accept': 'application/json'}
    if api_key:
        headers['apiKey'] = api_key 

    try:
        time.sleep(0.6 if api_key else 6.0)
        response = requests.get(NVD_API, params=params, headers=headers, timeout=15)

        if response.status_code == 200:
            data = response.json()
            items = data.get("vulnerabilities", [])
            if not items: return []
                
            parsed_results = []
            context_lower = str(service_context).lower()
            
            for item in items:
                cve = item.get("cve", {})
                desc_raw = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
                desc = desc_raw.lower()
                
                # --- 🛰️ STACK MISMATCH GATEKEEPER ---
                if any(x in desc for x in ["groovy", "java", "classpath", "tomcat", "coyote"]):
                    if not any(x in context_lower for x in ["tomcat", "coyote", "java", "jsp", "coyote"]):
                        continue 

                # --- 🧠 CONTEXTUAL VALIDATION & CONFIDENCE ---
                # Default is LOW for unverified version-based findings
                confidence = "LOW"
                cve_id = cve.get("id", "Unknown ID")
                
                # Upgrade to HIGH if the CVE is mentioned in your Nikto scan results
                if cve_id.lower() in context_lower:
                    confidence = "HIGH"

                conditional_keywords = ["proxy", "suexec", "cgi", "ldap", "xml-rpc", "openssl"]
                is_potential = any(key in desc for key in conditional_keywords)
                
                metrics = cve.get("metrics", {})
                score, severity = "N/A", "UNKNOWN"
                metric_keys = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
                
                for mk in metric_keys:
                    if mk in metrics:
                        m_data = metrics[mk][0].get("cvssData", metrics[mk][0])
                        score = m_data.get("baseScore", "N/A")
                        severity = m_data.get("baseSeverity", metrics[mk][0].get("baseSeverity", "UNKNOWN")).upper()
                        break

                if is_potential:
                    cve_id = f"[POTENTIAL] {cve_id}"

                # --- 🚀 ADDED: CVSS & Confidence Data Points ---
                parsed_results.append({
                    "cve_id": cve_id,
                    "description": desc_raw[:150],
                    "score": score,
                    "severity": severity,
                    "confidence": confidence  # Forensic weighting point
                })
            return parsed_results
            
    except Exception as e:
        print(f"   [API] Connection Exception: {e}")

    return []