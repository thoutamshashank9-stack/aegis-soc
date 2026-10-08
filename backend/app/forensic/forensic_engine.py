"""
Forensic Timeline, Header Chain, Hashing, and IOC extraction.
- Analyzes "Received" header chain chronologically (Sender -> Relays -> Ingest MTA)
- Extracts forensic timestamps and calculates hop latencies
- Generates SHA-256 integrity hash of raw email evidence
- Aggregates all Indicators of Compromise (IOCs) into exportable structured JSON
"""
import re
import hashlib
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Dict, Any, List

IPV4_REGEX = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'


from app.services.email_analyzer import extract_candidate_ips


class ForensicEngine:

    @staticmethod
    def calculate_sha256(raw_bytes: bytes) -> str:
        return hashlib.sha256(raw_bytes).hexdigest()

    @staticmethod
    def analyze_header_chain(received_headers: List[str]) -> List[Dict[str, Any]]:
        """
        Parses Received headers from bottom (origin/sender) to top (final recipient).
        Note: In RFC 5322, Received headers are prepended, so the earliest hop is at the bottom.
        """
        hops = []
        # Reverse to follow chronological order (earliest first)
        chronological_headers = list(reversed(received_headers))

        for idx, header in enumerate(chronological_headers):
            # Parse 'from <host>'
            from_match = re.search(r'from\s+([^\s;]+)', header, re.IGNORECASE)
            from_host = from_match.group(1) if from_match else "unknown"

            # Parse 'by <host>'
            by_match = re.search(r'by\s+([^\s;]+)', header, re.IGNORECASE)
            by_host = by_match.group(1) if by_match else "unknown"

            # Parse IP in hop (IPv4 or IPv6)
            ip_matches = extract_candidate_ips(header)
            relay_ip = ip_matches[0] if ip_matches else "none"

            # Parse timestamp after semicolon
            date_part = None
            dt_obj = None
            raw_date = "unknown"
            if ";" in header:
                raw_date = header.split(";")[-1].strip()
                try:
                    dt_obj = parsedate_to_datetime(raw_date)
                    date_part = dt_obj.isoformat()
                except Exception:
                    pass

            hops.append({
                "hop_order": idx + 1,
                "from_host": from_host,
                "by_host": by_host,
                "relay_ip": relay_ip,
                "raw_timestamp": raw_date,
                "iso_timestamp": date_part,
                "raw_header_snippet": header.strip()
            })

        return hops

    @staticmethod
    def build_forensic_timeline(email_data: Dict[str, Any], hops: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Constructs an integrated chronological forensic timeline."""
        timeline = []

        # 1. Add all hops in chronological sequence
        for hop in hops:
            timeline.append({
                "stage": f"Relay Hop #{hop['hop_order']}",
                "timestamp": hop["iso_timestamp"] or hop["raw_timestamp"],
                "description": f"Transferred from {hop['from_host']} to {hop['by_host']} (Relay: {hop['relay_ip']})",
                "component": "MTA Transfer",
                "type": "hop"
            })

        # 2. Date Header claimed by sender
        if email_data.get("date") and email_data["date"] != "not_available":
            timeline.append({
                "stage": "Client Claimed Date",
                "timestamp": email_data["date"],
                "description": f"Client user agent recorded message creation timestamp",
                "component": "MUA Client",
                "type": "client_date"
            })

        # 3. Security Analysis Ingestion
        timeline.append({
            "stage": "Forensic Ingestion & Hashing",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "description": "Evidence received by SOC forensic sandbox pipeline; cryptographic SHA-256 generated",
            "component": "SOC Threat Engine",
            "type": "forensic_analysis"
        })

        return timeline

    @staticmethod
    def extract_iocs(email_data: Dict[str, Any], url_analyses: List[Dict[str, Any]], sha256_hash: str) -> Dict[str, List[Dict[str, str]]]:
        """Collects all Indicators of Compromise for threat hunting and SIEM export."""
        iocs = {
            "ips": [],
            "domains": [],
            "urls": [],
            "emails": [],
            "hashes": [],
            "attachments": []
        }

        # IP IOCs
        for ip_info in email_data.get("ips", []):
            iocs["ips"].append({
                "value": ip_info["ip"],
                "type": "ipv4",
                "context": f"Found in {ip_info['source']}",
                "is_private": ip_info.get("is_private", False)
            })

        # Domain IOCs
        for d in email_data.get("domains", []):
            iocs["domains"].append({
                "value": d,
                "type": "domain",
                "context": "Identified in email headers or hyperlink destinations"
            })

        # URL IOCs
        for u in url_analyses:
            iocs["urls"].append({
                "value": u["url"],
                "type": "url",
                "context": f"Destination host {u['host']} (Suspicious: {u['is_suspicious']})"
            })

        # Email IOCs
        if email_data.get("sender_email") and email_data["sender_email"] != "unknown":
            iocs["emails"].append({
                "value": email_data["sender_email"],
                "type": "sender_address",
                "context": "Claimed sender"
            })
        if email_data.get("reply_to") and email_data["reply_to"] != "not_available":
            iocs["emails"].append({
                "value": email_data["reply_to"],
                "type": "reply_to_address",
                "context": "Header reply destination"
            })

        # Evidence Hash IOC
        iocs["hashes"].append({
            "value": sha256_hash,
            "type": "sha256",
            "context": "Cryptographic fingerprint of email artifact"
        })

        # Attachments
        for att in email_data.get("attachments", []):
            iocs["attachments"].append({
                "value": att["filename"],
                "type": "filename",
                "context": f"MIME type: {att.get('content_type')}, size: {att.get('size_bytes')} bytes"
            })

        return iocs
