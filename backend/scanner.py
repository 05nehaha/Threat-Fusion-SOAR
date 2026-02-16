import nmap
import subprocess
import os
import signal
from urllib.parse import urlparse

def run_nmap_scan(target):
    """
    Runs an Nmap scan with service version and CPE detection.
    SAFE: Automatically strips http/https so Nmap doesn't crash.
    """
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        clean_target = parsed.netloc
    else:
        clean_target = target

    nm = nmap.PortScanner()
    # T4 is good, but -F (Fast mode) is often better for a web dashboard 
    # so the user isn't waiting 10 minutes.
    nmap_args = os.getenv("NMAP_ARGS", "-sV -Pn -T4")

    try:
        nm.scan(clean_target, arguments=nmap_args)
    except Exception as e:
        print(f"[!] Nmap Error: {e}")
        return []

    scan_results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                service = nm[host][proto][port]
                cpes = service.get('cpes', [])

                # --- 🚀 ADDED: SERVICE PORT AWARENESS ---
                # Flags alternative management ports used by devs/admins
                service_name = service.get('name', 'unknown')
                if port in [8080, 8443, 9090, 10000]:
                    service_name = f"POTENTIAL-ADMIN-PANEL ({service_name})"

                scan_results.append({
                    "port": port,
                    "name": service_name,
                    "product": service.get('product', ''),
                    "version": service.get('version', ''),
                    "state": service.get('state', ''),
                    "cpe": cpes[0] if cpes else None
                })
    return scan_results


def run_nikto_scan(target):
    """
    Runs a Nikto scan using the system command line.
    Improved to prevent attribute errors during timeouts.
    """
    print(f"[*] Starting Nikto scan on: {target}")
    nikto_timeout = int(os.getenv("NIKTO_TIMEOUT", "300")) # 5 mins default
    nikto_maxtime = os.getenv("NIKTO_MAXTIME", "3m") 

    try:
        cmd = [
            "nikto",
            "-h", target,
            "-Tuning", "123",
            "-Display", "1",
            "-maxtime", nikto_maxtime
        ]

        # Use start_new_session=True to allow killing the entire process group
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True
        )

        try:
            stdout, stderr = p.communicate(timeout=nikto_timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
            # Kill the process group
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except Exception:
                p.kill()
            
            # Capture what we can after the kill
            stdout, stderr = p.communicate()

        stdout = (stdout or "").strip()
        stderr = (stderr or "").strip()

        out = stdout
        if stderr:
            out += f"\n\n[nikto stderr]\n{stderr}"
        if timed_out:
            out += f"\n\n[nikto] ERROR: Host maximum execution time of {nikto_timeout}s reached"
            
        return out

    except Exception as e:
        return f"Nikto scan failed: {str(e)}"

if __name__ == "__main__":
    test_target = "testphp.vulnweb.com" 
    # Quick debug test for Nmap logic
    print(f"[*] Running test on {test_target}...")
    results = run_nmap_scan(test_target)
    for res in results:
        print(f"Port {res['port']}: {res['name']}")