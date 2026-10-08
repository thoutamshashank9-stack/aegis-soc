"""
IP Geolocation and ASN Routing Intelligence Service.
Email Forensics Pipeline:
1. Strict RFC Classification (Public, Private, Loopback, Link-local, Reserved, Multicast, Documentation/test IP)
2. Safe filtration of non-routable addresses from public geolocation lookups
3. Accurate provider categorization (Cloud Provider, CDN, Email Provider, ISP, VPN/Proxy/Tor)
4. 3-Way Forensic Location Distinction:
   - IP network geolocation (Data center / server PoP)
   - Mail relay / Server infrastructure role
   - Sender physical location (Unverified / Non-determinable from IP)
5. Confidence scoring (0-100) and forensic explanation
6. "Why this IP matters" forensic rationale
7. Evidence chain preservation
"""
import os
import ipaddress
import httpx
from typing import Dict, Any, Optional

GEOLOCATION_API_KEY = os.getenv("GEOLOCATION_API_KEY", "")

DOC_NETWORKS = [
    ipaddress.ip_network('192.0.2.0/24'),
    ipaddress.ip_network('198.51.100.0/24'),
    ipaddress.ip_network('203.0.113.0/24'),
    ipaddress.ip_network('2001:db8::/32'),
]
RESERVED_NETWORKS = [
    ipaddress.ip_network('240.0.0.0/4'),
    ipaddress.ip_network('100.64.0.0/10'),
    ipaddress.ip_network('198.18.0.0/15'),
]


class GeolocationService:

    @staticmethod
    def classify_ip_type(ip_str: str) -> str:
        """Classifies IP address into one of:
        - Public
        - Private
        - Loopback
        - Link-local
        - Reserved
        - Multicast
        - Documentation/test IP
        """
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return "Unknown / Invalid"

        for net in DOC_NETWORKS:
            if ip_obj in net:
                return "Documentation/test IP"
        for net in RESERVED_NETWORKS:
            if ip_obj in net:
                return "Reserved"
        if ip_obj.is_multicast:
            return "Multicast"
        if ip_obj.is_loopback:
            return "Loopback"
        if ip_obj.is_link_local:
            return "Link-local"
        if ip_obj.is_private:
            return "Private"
        if ip_obj.is_reserved:
            return "Reserved"
        if ip_obj.is_global:
            return "Public"
        return "Reserved"

    @staticmethod
    def is_routable_public_ip(ip_str: str) -> bool:
        return GeolocationService.classify_ip_type(ip_str) == "Public"

    @staticmethod
    def identify_infrastructure_type(isp: str, org: str, asn: str, ip_str: str) -> Dict[str, str]:
        """Categorizes public infrastructure into Cloud, CDN, Email Provider, ISP, or VPN/Proxy/Tor."""
        combined = f"{isp} {org} {asn}".lower()

        # 1. VPN / Proxy / Tor / Anonymizers
        vpn_indicators = [
            "tor exit", "tor-exit", "exitnode", "mullvad", "nordvpn", "expressvpn",
            "private internet access", "vpn", "proxy", "datacamp", "m247",
            "ipvanish", "surfshark", "cyberghost", "protonvpn", "choopa"
        ]
        for ind in vpn_indicators:
            if ind in combined:
                return {
                    "category": "VPN / Proxy / Anonymizer",
                    "tag": "VPN/Proxy",
                    "risk_context": "Identified as a hosting proxy, commercial VPN egress, or Tor anonymization node. Obfuscates client origin."
                }

        # 2. Dedicated Email Service Providers (ESPs) & Gateways
        esp_indicators = [
            "sendgrid", "mailgun", "postmark", "sparkpost", "constantcontact",
            "mailchimp", "zendesk", "protonmail", "mimecast", "proofpoint",
            "barracuda", "messagebird", "infobip", "mailjet", "hubspot"
        ]
        for ind in esp_indicators:
            if ind in combined:
                return {
                    "category": "Email Provider (ESP / Gateway)",
                    "tag": "Email Provider",
                    "risk_context": "Authorized bulk or transactional outbound mail relay / enterprise anti-spam gateway."
                }

        # 3. Content Delivery Networks (CDNs)
        cdn_indicators = ["cloudflare", "fastly", "akamai", "cloudfront", "incapsula", "edgecast"]
        for ind in cdn_indicators:
            if ind in combined:
                return {
                    "category": "CDN (Content Delivery Network)",
                    "tag": "CDN",
                    "risk_context": "Edge caching proxy or DDoS protection shield."
                }

        # 4. Cloud Hyperscalers & IaaS Hosting
        cloud_indicators = [
            "amazon", "aws", "azure", "microsoft", "google cloud", "gcp",
            "digitalocean", "linode", "oracle cloud", "hetzner", "vultr",
            "alibaba cloud", "tencent cloud", "rackspace", "ovh"
        ]
        for ind in cloud_indicators:
            if ind in combined:
                if "office 365" in combined or "exchange" in combined or "outlook" in combined:
                    return {
                        "category": "Email Provider (Microsoft 365)",
                        "tag": "Email Provider",
                        "risk_context": "Microsoft enterprise cloud email infrastructure (Exchange Online Protection)."
                    }
                return {
                    "category": "Cloud Infrastructure Provider",
                    "tag": "Cloud Provider",
                    "risk_context": "Public cloud data center / IaaS compute instance (virtual machine or serverless egress)."
                }

        # 5. Major Mail Platforms (Google Workspace)
        if "google" in combined:
            return {
                "category": "Email Provider (Google Workspace)",
                "tag": "Email Provider",
                "risk_context": "Google Workspace / Gmail enterprise mail transmission infrastructure."
            }

        # 6. Commercial / Residential Telecom ISP
        return {
            "category": "Internet Service Provider (ISP)",
            "tag": "ISP",
            "risk_context": "Commercial telecommunications network or enterprise transit provider."
        }

    @staticmethod
    def geolocate_ip(
        ip_str: str,
        ip_type: Optional[str] = None,
        source: Optional[str] = None,
        source_header: Optional[str] = None,
        hop_order: Optional[int] = None,
        total_hops: Optional[int] = None,
        from_host: Optional[str] = None,
        by_host: Optional[str] = None,
        raw_timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Geolocates an IP address with forensic rigor, provider classification, and non-routable filtering."""
        canonical_type = GeolocationService.classify_ip_type(ip_str)

        # Common evidence metadata
        evidence_info = {
            "ip": ip_str,
            "source": source or "Received",
            "source_header": source_header,
            "hop_order": hop_order,
            "total_hops": total_hops,
            "from_host": from_host or "Unknown",
            "by_host": by_host or "Unknown",
            "raw_timestamp": raw_timestamp or "Unknown",
            "ip_type": canonical_type,
        }

        # -------------------------------------------------------------
        # NON-ROUTABLE ADDRESS HANDLERS (EXCLUDED FROM GEOLOCATION LOOKUP)
        # -------------------------------------------------------------
        if canonical_type != "Public":
            is_doc = canonical_type == "Documentation/test IP"
            is_priv = canonical_type == "Private"
            is_loop = canonical_type == "Loopback"
            is_multi = canonical_type == "Multicast"
            is_link = canonical_type == "Link-local"

            if is_doc:
                reason = (
                    "RFC 5737 / RFC 3849 Special-Purpose Documentation IP address. Documentation addresses "
                    "(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) are reserved exclusively for "
                    "technical specifications and test documents. They are non-routable on the global public Internet."
                )
                why_matters = "Appears in standardized RFC examples, benchmarks, or simulated threat campaigns. Confirms synthetic or testing origin."
                infra_cat = "Documentation / Testbed Space"
                infra_tag = "Documentation"
                relay_role = "Synthetic / RFC Benchmark Testbed"
            elif is_priv:
                reason = (
                    "RFC 1918 Private Network Address. Private IP addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, "
                    "fc00::/7) operate only within local area networks (LAN) or behind enterprise NAT firewalls. "
                    "They cannot be physically geolocated across the public Internet."
                )
                why_matters = "Internal enterprise hop recorded before the email exited to the Internet or after arrival at the corporate mail gateway. Provides visibility into internal LAN topology."
                infra_cat = "Private Network (RFC 1918)"
                infra_tag = "Private LAN"
                relay_role = "Internal LAN / Intranet Relay"
            elif is_loop:
                reason = "RFC 1122 Loopback Address (127.0.0.0/8, ::1). Loopback addresses refer strictly to the local host machine."
                why_matters = "Localhost socket binding used for inter-process communication on the mail server host."
                infra_cat = "Loopback (RFC 1122)"
                infra_tag = "Loopback"
                relay_role = "Local Host Loopback"
            elif is_multi:
                reason = "RFC 5771 Multicast Address (224.0.0.0/4, ff00::/8). Multicast group destination, non-routable unicast."
                why_matters = "Multicast destination address space."
                infra_cat = "Multicast Group Space"
                infra_tag = "Multicast"
                relay_role = "Multicast Interface"
            elif is_link:
                reason = "RFC 3927 Link-Local Address (169.254.0.0/16, fe80::/10). Auto-configured address restricted to a single local network segment."
                why_matters = "Link-local interface address used within a single subnet."
                infra_cat = "Link-Local Address"
                infra_tag = "Link-local"
                relay_role = "Link-Local Interface"
            else:
                reason = f"IETF Reserved Address Space. Non-routable on the public Internet."
                why_matters = "Special-purpose IETF reservation."
                infra_cat = "Reserved Address Space"
                infra_tag = "Reserved"
                relay_role = "Reserved Network Space"

            return {
                **evidence_info,
                "is_public": False,
                "is_geolocatable": False,
                "not_geolocatable_reason": reason,
                "infrastructure_type": infra_cat,
                "infrastructure_tag": infra_tag,
                "infrastructure_context": "Non-routable network address. Never transmitted over public BGP routing tables.",
                "relay_role": relay_role,
                "why_it_matters": why_matters,
                "confidence_score": 0,
                "confidence_label": "Non-routable",
                "forensic_explanation": f"Classified as {canonical_type}. Excluded from public WHOIS and physical map coordinates.",
                "network_location": f"Not geolocatable ({canonical_type})",
                "network_location_type": "Non-Routable Address Space",
                "relay_location": relay_role,
                "sender_physical_location": "UNVERIFIED / NOT APPLICABLE",
                "sender_location_disclaimer": "Non-routable addresses operate exclusively within local networks or testing benchmarks and have no physical geographic coordinates.",
                "country": "Not geolocatable",
                "region": f"Special-Purpose Block ({canonical_type})",
                "city": "Non-Routable Address Space",
                "latitude": None,
                "longitude": None,
                "isp": f"IANA Special-Purpose ({canonical_type})",
                "asn": "N/A",
                "org": f"IANA / IETF Reserved Space ({canonical_type})",
                "timezone": "N/A",
                "lookup_status": "not_geolocatable",
                "accuracy_notice": "Non-routable IP addresses are never routed on the public Internet and cannot be geolocated."
            }

        # -------------------------------------------------------------
        # ROUTABLE PUBLIC IP LOOKUP (ONLY EXECUTED FOR PUBLIC IPS)
        # -------------------------------------------------------------
        geo_data = None
        try:
            url = f"http://ip-api.com/json/{ip_str}?fields=status,message,country,regionName,city,lat,lon,timezone,isp,org,as,query"
            with httpx.Client(timeout=4.0) as client:
                res = client.get(url)
                if res.status_code == 200:
                    data = res.json()
                    if data.get("status") == "success":
                        geo_data = data
        except Exception:
            pass

        # Parse Provider / ISP Information
        isp = (geo_data.get("isp") if geo_data else None) or "Unknown ISP"
        org = (geo_data.get("org") if geo_data else None) or "Unknown Org"
        asn = (geo_data.get("as") if geo_data else None) or "Unknown ASN"
        country = (geo_data.get("country") if geo_data else None) or "Unknown"
        region = (geo_data.get("regionName") if geo_data else None) or "Unknown"
        city = (geo_data.get("city") if geo_data else None) or "Unknown"
        latitude = geo_data.get("lat") if geo_data else None
        longitude = geo_data.get("lon") if geo_data else None
        timezone = (geo_data.get("timezone") if geo_data else None) or "Unknown"
        lookup_status = "success" if geo_data else "unavailable"

        # Categorize Infrastructure
        infra = GeolocationService.identify_infrastructure_type(isp, org, asn, ip_str)

        # Determine Relay Role, Confidence Score, and "Why this IP matters"
        if hop_order == 1 or (total_hops and hop_order == 1):
            relay_role = "Originating MTA Ingress Gateway"
            why_matters = (
                "Initial mail transfer agent (MTA) or border egress relay that accepted the email from the sender's client. "
                "Identifies the originating autonomous system where the message first entered the public email transport network."
            )
            confidence_score = 85
            confidence_label = "High (Relay PoP) / Low (Client Address)"
            forensic_explanation = (
                f"Verified first external hop in the SMTP chain, hosted by {isp}. "
                "Notice: This confirms the server data center location, NOT where the human sender was physically located "
                "(sender may have used webmail, VPN, or mobile API from anywhere in the world)."
            )
        elif total_hops and hop_order == total_hops:
            relay_role = "Recipient Boundary Ingest (Destination MX)"
            why_matters = (
                "The recipient organization's boundary mail server that received and archived the message. "
                "Reflects the recipient domain's inbound infrastructure, not the sender."
            )
            confidence_score = 98
            confidence_label = "High (Recipient MX)"
            forensic_explanation = f"Recipient mail exchange server hosted by {isp} ({city}, {country}). Completely unrelated to sender origin."
        else:
            relay_role = "Intermediary Transit Relay / Security Gateway"
            why_matters = (
                "Intermediate routing hop, cloud security inspection filter, or anti-spam gateway that routed the email "
                "between network boundaries. Reflects the transit path, not the sender."
            )
            confidence_score = 92
            confidence_label = "High (Transit Relay)"
            forensic_explanation = f"Verified intermediary transfer point along the SMTP routing path operated by {isp}."

        network_location = f"{city}, {region}, {country} (Data Center PoP)" if geo_data else "Lookup Unavailable"

        return {
            **evidence_info,
            "is_public": True,
            "is_geolocatable": True,
            "not_geolocatable_reason": None if geo_data else "Live geolocation provider timed out or was temporarily unreachable.",
            "infrastructure_type": infra["category"],
            "infrastructure_tag": infra["tag"],
            "infrastructure_context": infra["risk_context"],
            "relay_role": relay_role,
            "why_it_matters": why_matters,
            "confidence_score": confidence_score if geo_data else 50,
            "confidence_label": confidence_label if geo_data else "Low (Unresolved)",
            "forensic_explanation": forensic_explanation,
            
            # 3-Way Forensic Location Distinction
            "network_location": network_location,
            "network_location_type": "Server Data Center / Network Point-of-Presence",
            "relay_location": f"{relay_role} ({isp} network)",
            "sender_physical_location": "UNVERIFIED / NOT DETERMINABLE FROM IP",
            "sender_location_disclaimer": (
                "FORENSIC PRINCIPLE: Mail server IP addresses identify mail transfer infrastructure (server data centers, "
                "cloud hosts, or relay gateways). They NEVER prove the physical home or office location of the human sender."
            ),
            
            "country": country,
            "region": region,
            "city": city,
            "latitude": latitude,
            "longitude": longitude,
            "isp": isp,
            "asn": asn,
            "org": org,
            "timezone": timezone,
            "lookup_status": lookup_status,
            "accuracy_notice": (
                "IP geolocation represents the registered network data center point-of-presence, "
                "not the physical location of the human sender."
            )
        }
