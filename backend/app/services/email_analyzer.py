"""
Email Analysis Engine.
Responsible for:
- Safe parsing of .eml and raw email text using Python standard email parser
- Extracting envelope and core headers (From, To, Subject, Message-ID, Return-Path, Reply-To, Date, Received)
- Extracting URLs, IP addresses, domains
- Detecting attachments and MIME types
- Extracting SPF, DKIM, DMARC from Authentication-Results and Received-SPF
- Strict adherence to truthfulness: "unknown" or "not_available" if missing
"""
import re
import ipaddress
import email
from email import policy
from email.parser import BytesParser, Parser
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional


EMAIL_REGEX = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
# Strict IPv4 regex
IPV4_REGEX = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
URL_REGEX = r'https?://[^\s<>"\')]+'


DOC_NETWORKS = [
    ipaddress.ip_network('192.0.2.0/24'),
    ipaddress.ip_network('198.51.100.0/24'),
    ipaddress.ip_network('203.0.113.0/24'),
    ipaddress.ip_network('2001:db8::/32'),
]
BENCHMARK_NETWORKS = [
    ipaddress.ip_network('198.18.0.0/15'),
]


def is_ip_valid(ip_str: str) -> bool:
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def is_ipv6_valid(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return isinstance(ip, ipaddress.IPv6Address)
    except ValueError:
        return False


def classify_ip_type(ip_str: str) -> str:
    """Classifies IP address into:
    - Public
    - Private
    - Loopback
    - Link-local
    - Reserved
    - Multicast
    - Documentation/test IP
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return "Unknown / Invalid"
    for net in DOC_NETWORKS:
        if ip in net:
            return "Documentation/test IP"
    for net in BENCHMARK_NETWORKS:
        if ip in net:
            return "Reserved"
    if ip.is_multicast:
        return "Multicast"
    if ip.is_loopback:
        return "Loopback"
    if ip.is_link_local:
        return "Link-local"
    if ip.is_private:
        return "Private"
    if ip.is_reserved:
        return "Reserved"
    if ip.is_global:
        return "Public"
    return "Reserved"


def is_private_or_reserved_ip(ip_str: str) -> bool:
    t = classify_ip_type(ip_str)
    return t != "Public"


def extract_candidate_ips(text: str) -> List[str]:
    """Extracts both IPv4 and IPv6 addresses from freeform header or body text."""
    found = []
    # 1. IPv4 matches
    ipv4s = re.findall(IPV4_REGEX, text)
    for ip in ipv4s:
        clean_ip = ip.strip()
        if is_ip_valid(clean_ip) and clean_ip not in found:
            found.append(clean_ip)

    # 2. IPv6 bracketed matches e.g. [2001:db8::1] or [IPv6:2001:db8::1]
    bracket_matches = re.findall(r'\[(?:IPv6:)?([a-fA-F0-9:.]+)\]', text, re.IGNORECASE)
    for cand in bracket_matches:
        cand_clean = cand.strip()
        if ":" in cand_clean and is_ipv6_valid(cand_clean) and cand_clean not in found:
            found.append(cand_clean)

    # 3. Unbracketed IPv6 tokens (with at least 2 colons)
    tokens = re.findall(r'(?:\s|^)([a-fA-F0-9]{1,4}(?::[a-fA-F0-9]{0,4}){2,7})(?:\s|;|$)', text)
    for tok in tokens:
        clean_tok = tok.strip()
        if ":" in clean_tok and is_ipv6_valid(clean_tok) and clean_tok not in found:
            found.append(clean_tok)

    return found


def extract_domain(email_or_url: str) -> Optional[str]:
    if not email_or_url:
        return None
    if "@" in email_or_url:
        parts = email_or_url.split("@")
        return parts[-1].strip(">").strip().lower()
    parsed = urlparse(email_or_url)
    if parsed.netloc:
        netloc = parsed.netloc.split(":")[0].lower()
        return netloc
    return None


class EmailAnalyzer:
    """Safe parser and extractor for email forensic metadata."""

    @staticmethod
    def parse_raw_bytes(content: bytes) -> Dict[str, Any]:
        """Parses raw email bytes with modern email policy."""
        try:
            msg = BytesParser(policy=policy.default).parsebytes(content)
        except Exception:
            # Fallback to compat32 policy if default fails on malformed input
            msg = BytesParser(policy=policy.compat32).parsebytes(content)
        return EmailAnalyzer._extract_structured_data(msg, raw_bytes=content)

    @staticmethod
    def parse_raw_text(text: str) -> Dict[str, Any]:
        """Parses raw email string."""
        raw_bytes = text.encode("utf-8", errors="replace")
        try:
            msg = Parser(policy=policy.default).parsestr(text)
        except Exception:
            msg = Parser(policy=policy.compat32).parsestr(text)
        return EmailAnalyzer._extract_structured_data(msg, raw_bytes=raw_bytes)

    @staticmethod
    def _extract_structured_data(msg, raw_bytes: bytes) -> Dict[str, Any]:
        # Core header extraction
        sender = str(msg.get("From", "unknown"))
        recipient = str(msg.get("To", "unknown"))
        subject = str(msg.get("Subject", "(No Subject)"))
        message_id = str(msg.get("Message-ID", "not_available"))
        return_path = str(msg.get("Return-Path", "not_available"))
        reply_to = str(msg.get("Reply-To", "not_available"))
        date_header = str(msg.get("Date", "not_available"))

        # Extract email address and display name from 'From'
        sender_email = "unknown"
        sender_display = "unknown"
        from_matches = re.findall(EMAIL_REGEX, sender)
        if from_matches:
            sender_email = from_matches[0].lower()
            # Clean display name
            display_candidate = re.sub(r'<.*?>', '', sender).strip().strip('"').strip("'")
            sender_display = display_candidate if display_candidate else sender_email

        # Sender domain
        sender_domain = extract_domain(sender_email) if sender_email != "unknown" else "unknown"

        # Received headers
        received_headers = [str(r) for r in msg.get_all("Received", [])]

        # Extract Authentication Results (SPF, DKIM, DMARC)
        auth_results = EmailAnalyzer._extract_auth_results(msg)

        # Body extraction (Plain & HTML)
        body_text = ""
        body_html = ""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                is_attachment = "attachment" in content_disposition.lower() or part.get_filename() is not None

                if is_attachment:
                    filename = part.get_filename() or "unnamed_attachment"
                    payload = part.get_payload(decode=True) or b""
                    attachments.append({
                        "filename": filename,
                        "content_type": content_type,
                        "size_bytes": len(payload),
                        "is_suspicious": False  # Evaluated by threat engine
                    })
                elif content_type == "text/plain" and not body_text:
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or "utf-8"
                        body_text = payload.decode(charset, errors="replace") if payload else ""
                    except Exception:
                        body_text = str(part.get_payload() or "")
                elif content_type == "text/html" and not body_html:
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or "utf-8"
                        body_html = payload.decode(charset, errors="replace") if payload else ""
                    except Exception:
                        body_html = str(part.get_payload() or "")
        else:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or "utf-8"
            content_type = msg.get_content_type()
            decoded = payload.decode(charset, errors="replace") if payload else str(msg.get_payload() or "")
            if content_type == "text/html":
                body_html = decoded
            else:
                body_text = decoded

        # URL Extraction
        full_text_search = f"{subject}\n{body_text}\n{body_html}"
        raw_urls = re.findall(URL_REGEX, full_text_search)
        urls = sorted(list(set(raw_urls)))

        # IP Extraction from Received headers and body
        ips = EmailAnalyzer._extract_all_ips(received_headers, full_text_search)

        # Domain Extraction from URLs and sender
        domains = set()
        if sender_domain and sender_domain != "unknown":
            domains.add(sender_domain)
        for u in urls:
            dom = extract_domain(u)
            if dom:
                domains.add(dom)

        # Build list of all headers
        all_headers = []
        for header_name, header_value in msg.items():
            all_headers.append({
                "name": header_name,
                "value": str(header_value)
            })

        return {
            "sender": sender,
            "sender_email": sender_email,
            "sender_display": sender_display,
            "sender_domain": sender_domain,
            "recipient": recipient,
            "subject": subject,
            "message_id": message_id,
            "return_path": return_path,
            "reply_to": reply_to,
            "date": date_header,
            "body_text": body_text,
            "body_html": body_html,
            "urls": urls,
            "ips": ips,
            "domains": sorted(list(domains)),
            "attachments": attachments,
            "received_headers": received_headers,
            "all_headers": all_headers,
            "authentication": auth_results
        }

    @staticmethod
    def _extract_auth_results(msg) -> Dict[str, str]:
        """Strictly extracts SPF, DKIM, and DMARC verification status."""
        spf = "unknown"
        dkim = "unknown"
        dmarc = "unknown"

        # Check Authentication-Results
        auth_headers = msg.get_all("Authentication-Results", [])
        combined_auth = " ".join([str(h).lower() for h in auth_headers])

        if "spf=" in combined_auth:
            match = re.search(r'spf=([a-z]+)', combined_auth)
            if match:
                spf = match.group(1)
        elif msg.get("Received-SPF"):
            # e.g., Received-SPF: Pass ... or Fail ...
            spf_val = str(msg.get("Received-SPF")).lower()
            first_word = spf_val.split()[0].rstrip(";:,").strip()
            if first_word in ["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"]:
                spf = first_word

        if "dkim=" in combined_auth:
            match = re.search(r'dkim=([a-z]+)', combined_auth)
            if match:
                dkim = match.group(1)
        elif msg.get("DKIM-Signature"):
            # Signature exists but without receiver validation record
            dkim = "present_unverified"

        if "dmarc=" in combined_auth:
            match = re.search(r'dmarc=([a-z]+)', combined_auth)
            if match:
                dmarc = match.group(1)

        return {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc
        }

    @staticmethod
    def _extract_all_ips(received_headers: List[str], full_text: str) -> List[Dict[str, Any]]:
        ip_map = {}
        total_received = len(received_headers)

        # 1. First priority: Received headers (relay hops)
        for idx, rec in enumerate(received_headers):
            # In RFC 5322 Received headers are prepended; earliest hop is at bottom
            chronological_hop = total_received - idx
            from_match = re.search(r'from\s+([^\s;]+)', rec, re.IGNORECASE)
            by_match = re.search(r'by\s+([^\s;]+)', rec, re.IGNORECASE)
            from_host = from_match.group(1) if from_match else "Unknown"
            by_host = by_match.group(1) if by_match else "Unknown"
            raw_ts = rec.split(";")[-1].strip() if ";" in rec else "Unknown"

            found_ips = extract_candidate_ips(rec)
            for ip in found_ips:
                if ip not in ip_map:
                    ip_type = classify_ip_type(ip)
                    is_non_public = ip_type.lower() not in ["public"]
                    
                    if chronological_hop == 1:
                        why_matters = "Originating MTA gateway: accepts email from sender client and dispatches onto Internet."
                    elif chronological_hop == total_received:
                        why_matters = "Destination recipient MX: inbound boundary gateway accepting email for local mailbox."
                    else:
                        why_matters = "Intermediary transit relay / security filter routing email between network boundaries."

                    ip_map[ip] = {
                        "ip": ip,
                        "source": "Received",
                        "header": rec.strip(),
                        "type": ip_type,
                        "hop_index": idx + 1,
                        "hop_order": chronological_hop,
                        "total_hops": total_received,
                        "from_host": from_host,
                        "by_host": by_host,
                        "raw_timestamp": raw_ts,
                        "why_it_matters": why_matters,
                        "is_private": is_non_public
                    }

        # 2. Second priority: Body text
        body_ips = extract_candidate_ips(full_text)
        for ip in body_ips:
            if ip not in ip_map:
                ip_type = classify_ip_type(ip)
                ip_map[ip] = {
                    "ip": ip,
                    "source": "Body",
                    "header": None,
                    "type": ip_type,
                    "hop_index": None,
                    "hop_order": None,
                    "total_hops": total_received,
                    "from_host": "None",
                    "by_host": "None",
                    "raw_timestamp": "None",
                    "why_it_matters": "Extracted from message body text payload (potential phishing link host or referenced IP).",
                    "is_private": ip_type.lower() not in ["public"]
                }

        return list(ip_map.values())
