import requests
import time

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_cves_dynamically(product=None, version=None, cpe=None, limit=5):
    """
    Fetches CVEs with CVSS Score & Severity.
    """
    
    # 1. Clean Inputs
    product = str(product).split('/')[0].strip().lower() if product else None
    version = str(version).strip() if version else None
    cpe = str(cpe).strip() if cpe else None
    
    results = []
    
    # --- ATTEMPT 1: Specific Search ---
    params = {"resultsPerPage": limit}
    
    if cpe:
        params["cpeName"] = cpe
        print(f"   [API] 🔍 Attempt 1 (CPE): {cpe}")
    elif product and version:
        params["keywordSearch"] = f"{product} {version}"
        print(f"   [API] 🔍 Attempt 1 (Specific): {product} {version}")
    elif product:
        params["keywordSearch"] = product
        print(f"   [API] 🔍 Attempt 1 (Product Only): {product}")
    else:
        return []

    results = call_nvd_api(params)
    
    # --- ATTEMPT 2: Broad Search (Fallback) ---
    if not results and product and version:
        print(f"   [API] ⚠️ No results for specific version. Trying broader search: {product}")
        params = {"keywordSearch": product, "resultsPerPage": limit}
        results = call_nvd_api(params)

    return results

def call_nvd_api(params):
    """Helper function to perform the request and parse CVSS."""
    headers = {
        'User-Agent': 'VulnerabilityScanner/1.0',
        'Accept': 'application/json'
    }
    
    try:
        time.sleep(0.6)
        response = requests.get(NVD_API, params=params, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            items = data.get("vulnerabilities", [])
            
            if not items:
                return []
                
            print(f"   [API] ✅ Success. Found {len(items)} CVEs.")
            
            parsed_results = []
            for item in items:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "UNKNOWN")
                
                # --- NEW: Extract CVSS Score & Severity ---
                metrics = cve.get("metrics", {})
                score = "N/A"
                severity = "UNKNOWN"

                # Try CVSS v3.1 (Newest)
                if "cvssMetricV31" in metrics:
                    v3 = metrics["cvssMetricV31"][0]["cvssData"]
                    score = v3.get("baseScore", "N/A")
                    severity = v3.get("baseSeverity", "UNKNOWN")
                # Try CVSS v3.0 (Older)
                elif "cvssMetricV30" in metrics:
                    v3 = metrics["cvssMetricV30"][0]["cvssData"]
                    score = v3.get("baseScore", "N/A")
                    severity = v3.get("baseSeverity", "UNKNOWN")
                # Fallback to CVSS v2 (Oldest)
                elif "cvssMetricV2" in metrics:
                    v2 = metrics["cvssMetricV2"][0]
                    score = v2["cvssData"].get("baseScore", "N/A")
                    # V2 puts severity in 'baseSeverity' or we imply it
                    severity = v2.get("baseSeverity", "MEDIUM") 

                # Get description
                desc = next(
                    (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), 
                    "No description"
                )
                
                parsed_results.append({
                    "cve_id": cve_id,
                    "description": desc,
                    "score": score,
                    "severity": severity
                })
            return parsed_results
            
        elif response.status_code == 403:
            print("   [API] ❌ Error 403: Rate Limited.")
        else:
            print(f"   [API] ❌ Error {response.status_code}")
            
    except Exception as e:
        print(f"   [API] Connection Error: {e}")

    return []