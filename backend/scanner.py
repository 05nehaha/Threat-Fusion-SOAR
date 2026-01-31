import nmap
import subprocess
from urllib.parse import urlparse

def run_nmap_scan(target):
    """
    Runs an Nmap scan with service version and CPE detection.
    SAFE: Automatically strips http/https so Nmap doesn't crash.
    """
    
    # 1. CLEAN THE TARGET URL (Fixes the empty table issue)
    # If the user sends "http://testphp.vulnweb.com/", we convert it to "testphp.vulnweb.com"
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        clean_target = parsed.netloc # Gets the domain only
    else:
        clean_target = target

    nm = nmap.PortScanner()
    print(f"[*] Starting Nmap scan on: {clean_target}")

    # -sV : Service/version detection
    # -Pn : Skip host discovery (Critical for firewalled hosts)
    # -T4 : Faster execution
    try:
        nm.scan(clean_target, arguments='-sV -Pn -T4')
    except Exception as e:
        print(f"[!] Nmap Error: {e}")
        return []

    scan_results = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                service = nm[host][proto][port]

                # Nmap may return a list of CPEs
                cpes = service.get('cpes', [])

                scan_results.append({
                    "port": port,
                    "name": service.get('name', 'unknown'),
                    "product": service.get('product', ''),
                    "version": service.get('version', ''),
                    "state": service.get('state', ''),
                    "cpe": cpes[0] if cpes else None
                })

    return scan_results


def run_nikto_scan(target):
    """
    Runs a Nikto scan using the system command line.
    """
    print(f"[*] Starting Nikto scan on: {target}")

    try:
        # -h: target host
        # -Tuning 123: common vulnerability checks
        cmd = [
            "nikto",
            "-h", target,
            "-Tuning", "123",
            "-Display", "1"
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.stdout

    except Exception as e:
        return f"Nikto scan failed: {str(e)}"


if __name__ == "__main__":
    # Quick test
    test_target = "testphp.vulnweb.com" 
    nmap_data = run_nmap_scan(test_target)
    print(f"[+] Nmap found {len(nmap_data)} services")