def map_attack_and_mitigation(vulnerability):
    mapping = {
        "xss": (
            "Cross-Site Scripting (XSS), session hijacking",
            "Input validation, output encoding, Content Security Policy"
        ),
        "cookie": (
            "Session hijacking",
            "Enable HttpOnly and Secure cookie flags"
        ),
        "header": (
            "Clickjacking, XSS",
            "Configure security headers (CSP, X-Frame-Options)"
        ),
        "ssl": (
            "Man-in-the-Middle attack",
            "Use TLS 1.2+, strong ciphers, valid certificates"
        )
    }

    for key in mapping:
        if key in vulnerability.lower():
            return mapping[key]

    return ("Unknown attack", "Manual security review recommended")
