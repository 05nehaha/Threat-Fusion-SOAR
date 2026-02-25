def extract_vulnerabilities(nikto_output):
    """
    Extracts vulnerability keywords dynamically from Nikto output
    """
    detected = set()
    text = nikto_output.lower()

    if "xss" in text:
        detected.add("XSS")

    if "cookie" in text and "httponly" in text:
        detected.add("Insecure Cookie")

    if "x-frame-options" in text or "security header" in text:
        detected.add("Missing Security Headers")

    if "ssl" in text or "tls" in text:
        detected.add("Weak SSL/TLS")

    return list(detected)
