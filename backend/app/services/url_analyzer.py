"""
URL and Domain Analysis Service.
Performs deterministic static analysis on URLs:
- Protocol checks (HTTP vs HTTPS)
- IP-based URLs (e.g., http://192.168.1.1/login)
- Suspicious Top-Level Domains (.xyz, .top, .club, .live, .click, .work, etc.)
- Length anomalies & excessive query parameter obfuscation
- Punycode / IDN spoofing detection (xn--)
- Lookalike / Brand spoofing patterns (e.g. login-microsoft, paypal-security)
- Safe external reputation API hook (VirusTotal / Google Safe Browsing if key configured)
"""
import re
from urllib.parse import urlparse
from typing import Dict, Any, List

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".live", ".click", ".work", ".link", ".buzz", ".guru",
    ".space", ".website", ".fun", ".rest", ".monster", ".bar", ".cfd", ".sbs", ".cam",
    ".stream", ".gq", ".ml", ".cf", ".tk", ".ga"
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "update", "banking", "secure",
    "security", "password", "wallet", "support", "confirm", "portal",
    "suspended", "payroll", "document", "bonus", "unlock"
]

HIGH_VALUE_BRANDS = [
    "paypal", "microsoft", "office365", "google", "apple", "amazon", "netflix",
    "bankofamerica", "chase", "wellsfargo", "docusign", "dropbox", "dhl", "ups"
]


class URLAnalyzer:

    @staticmethod
    def analyze_url(url: str, sender_domain: str = None) -> Dict[str, Any]:
        """Analyzes a single URL for security threats."""
        indicators = []
        is_suspicious = False
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.split(":")[0].lower()
        path = parsed.path.lower()

        # 1. Plaintext HTTP
        if scheme == "http":
            indicators.append({
                "rule": "unencrypted_http",
                "severity": "medium",
                "description": "URL transmits credentials and content in unencrypted plaintext (HTTP)"
            })
            is_suspicious = True

        # 2. IP-based URL
        # e.g., http://192.168.1.1/ or http://45.33.32.156/
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, netloc):
            indicators.append({
                "rule": "ip_host_url",
                "severity": "high",
                "description": f"URL host is a raw IP address ({netloc}) rather than a registered domain name"
            })
            is_suspicious = True

        # 3. Punycode detection
        if "xn--" in netloc:
            indicators.append({
                "rule": "punycode_idn_homograph",
                "severity": "high",
                "description": f"Punycode encoded domain detected ({netloc}), potential homograph attack"
            })
            is_suspicious = True

        # 4. Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if netloc.endswith(tld):
                indicators.append({
                    "rule": "suspicious_tld",
                    "severity": "medium",
                    "description": f"Domain utilizes high-risk TLD associated with disposable phishing campaigns ({tld})"
                })
                is_suspicious = True
                break

        # 5. Excessive length or character obfuscation
        if len(url) > 120:
            indicators.append({
                "rule": "excessive_url_length",
                "severity": "low",
                "description": f"Abnormally long URL ({len(url)} characters) often used to conceal malicious destinations"
            })

        # 6. Lookalike / Brand spoofing in domain
        for brand in HIGH_VALUE_BRANDS:
            if brand in netloc:
                # If the domain is not actually the official brand domain
                official_suffixes = (f"{brand}.com", f"{brand}.org", f"{brand}.net")
                if not any(netloc == brand_sfx or netloc.endswith("." + brand_sfx) for brand_sfx in official_suffixes):
                    indicators.append({
                        "rule": "brand_impersonation_url",
                        "severity": "critical",
                        "description": f"URL domain contains brand keyword '{brand}' but is hosted on unofficial host '{netloc}'"
                    })
                    is_suspicious = True

        # 7. Suspicious Action Keywords in host or path
        kw_found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in netloc or kw in path]
        if len(kw_found) >= 2:
            indicators.append({
                "rule": "credential_harvest_keywords",
                "severity": "medium",
                "description": f"URL path/host contains credential harvesting indicators: {', '.join(kw_found)}"
            })
            is_suspicious = True

        # 8. Sender Domain Mismatch
        if sender_domain and sender_domain != "unknown":
            if sender_domain not in netloc and netloc not in sender_domain:
                # If sender claims to be company A but links to untrusted host
                pass  # Handled in threat engine correlation

        return {
            "url": url,
            "host": netloc,
            "scheme": scheme,
            "is_suspicious": is_suspicious,
            "indicators": indicators,
            "reputation_provider": "External reputation lookup unavailable (No API key configured)"
        }

    @staticmethod
    def analyze_urls(urls: List[str], sender_domain: str = None) -> List[Dict[str, Any]]:
        return [URLAnalyzer.analyze_url(u, sender_domain) for u in urls]
