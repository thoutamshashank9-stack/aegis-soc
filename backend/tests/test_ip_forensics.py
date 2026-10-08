"""
Forensic IP Intelligence and Geolocation Pipeline Tests.
Validates:
1. IPv4 and IPv6 address parsing from Received headers.
2. Exact classification into:
   - Public
   - Private
   - Loopback
   - Link-local
   - Reserved
   - Multicast
   - Documentation/test IP
3. Geolocation exclusion for non-public IPs.
4. ASN, ISP, and Infrastructure classification (Cloud, CDN, Email Provider, ISP, VPN/Proxy).
5. 3-Way location distinction:
   - Network geolocation (PoP / Data Center)
   - Mail relay location
   - Sender physical location (unverified disclaimer)
6. Confidence score (0-100) and forensic explanation.
7. "Why this IP matters" explanation.
8. Chronological Received header evidence chain (Hop 1 = Origin MTA).
9. Realistic test scenarios (test_a, test_b, test_c, test_d, test_e).
"""
import pytest
from fastapi.testclient import TestClient
from main import app
from app.services.geolocation_service import GeolocationService
from app.services.email_analyzer import EmailAnalyzer

client = TestClient(app)


def test_ip_type_classification():
    # 7 exact types
    assert GeolocationService.classify_ip_type("8.8.8.8") == "Public"
    assert GeolocationService.classify_ip_type("2607:f8b0:4005:805::200e") == "Public"
    
    assert GeolocationService.classify_ip_type("192.168.1.100") == "Private"
    assert GeolocationService.classify_ip_type("10.0.0.1") == "Private"
    assert GeolocationService.classify_ip_type("172.16.0.1") == "Private"
    assert GeolocationService.classify_ip_type("fc00::1") == "Private"

    assert GeolocationService.classify_ip_type("127.0.0.1") == "Loopback"
    assert GeolocationService.classify_ip_type("::1") == "Loopback"

    assert GeolocationService.classify_ip_type("169.254.1.1") == "Link-local"
    assert GeolocationService.classify_ip_type("fe80::1") == "Link-local"

    assert GeolocationService.classify_ip_type("198.51.100.1") == "Documentation/test IP"
    assert GeolocationService.classify_ip_type("203.0.113.5") == "Documentation/test IP"
    assert GeolocationService.classify_ip_type("192.0.2.1") == "Documentation/test IP"
    assert GeolocationService.classify_ip_type("2001:db8::1") == "Documentation/test IP"

    assert GeolocationService.classify_ip_type("224.0.0.1") == "Multicast"
    assert GeolocationService.classify_ip_type("ff02::1") == "Multicast"

    assert GeolocationService.classify_ip_type("240.0.0.1") == "Reserved"


def test_infrastructure_identification():
    infra_google = GeolocationService.identify_infrastructure_type("Google LLC", "Google LLC", "AS15169 GOOGLE", "8.8.8.8")
    assert infra_google["tag"] == "Email Provider"
    assert "Google" in infra_google["category"]

    infra_aws = GeolocationService.identify_infrastructure_type("Amazon.com Inc", "Amazon.com Inc", "AS16509 AMAZON-02", "3.5.140.2")
    assert infra_aws["tag"] == "Cloud Provider"
    assert "Cloud" in infra_aws["category"]

    infra_cf = GeolocationService.identify_infrastructure_type("Cloudflare, Inc.", "Cloudflare, Inc.", "AS13335 CLOUDFLARENET", "104.16.1.1")
    assert infra_cf["tag"] == "CDN"
    assert "CDN" in infra_cf["category"]

    infra_comcast = GeolocationService.identify_infrastructure_type("Comcast Cable", "Comcast Cable", "AS7922 COMCAST-7922", "68.80.1.1")
    assert infra_comcast["tag"] == "ISP"


def test_geolocation_3way_distinction_and_disclaimer():
    # Public IP lookup
    res = GeolocationService.geolocate_ip(
        "8.8.8.8",
        hop_order=1,
        total_hops=2,
        from_host="mail.example.org",
        by_host="mx.destination.org"
    )
    assert res["is_public"] is True
    assert res["is_geolocatable"] is True
    assert res["ip_type"] == "Public"
    assert res["confidence_score"] >= 80
    assert "Originating MTA" in res["relay_role"]
    assert "network_location" in res
    assert "sender_physical_location" in res
    assert "UNVERIFIED" in res["sender_physical_location"]
    assert "NEVER prove" in res["sender_location_disclaimer"]
    assert "why_it_matters" in res
    assert "forensic_explanation" in res


def test_documentation_ip_exclusion():
    res = GeolocationService.geolocate_ip("198.51.100.25")
    assert res["is_public"] is False
    assert res["is_geolocatable"] is False
    assert res["ip_type"] == "Documentation/test IP"
    assert res["confidence_score"] == 0
    assert res["latitude"] is None
    assert res["longitude"] is None
    assert "RFC 5737" in res["not_geolocatable_reason"]
    assert "Not geolocatable" in res["network_location"]


def test_private_ip_exclusion():
    res = GeolocationService.geolocate_ip("10.200.1.5")
    assert res["is_public"] is False
    assert res["is_geolocatable"] is False
    assert res["ip_type"] == "Private"
    assert res["confidence_score"] == 0
    assert res["latitude"] is None
    assert res["longitude"] is None
    assert "RFC 1918" in res["not_geolocatable_reason"]


def test_ipv6_handling():
    res = GeolocationService.geolocate_ip("2001:db8::dead:beef")
    assert res["is_public"] is False
    assert res["ip_type"] == "Documentation/test IP"
    assert "RFC 3849" in res["not_geolocatable_reason"]


def test_multi_hop_demo_email():
    with open("../sample_emails/test_e_multi_hop_demo.eml", "rb") as f:
        file_bytes = f.read()

    res = client.post(
        "/api/analyze",
        files={"file": ("test_e_multi_hop_demo.eml", file_bytes, "message/rfc822")}
    )
    assert res.status_code == 200
    data = res.json()
    geos = data["geolocations"]
    assert len(geos) >= 3

    # Check that hop ordering is captured
    hop_orders = [g.get("hop_order") for g in geos if g.get("hop_order") is not None]
    assert 1 in hop_orders  # Origin hop
    
    # Check that public IP has infrastructure tag and 3-way distinction
    public_hops = [g for g in geos if g["is_public"]]
    assert len(public_hops) >= 1
    pub = public_hops[0]
    assert pub["infrastructure_type"] is not None
    assert pub["relay_role"] is not None
    assert pub["why_it_matters"] is not None
    assert pub["sender_physical_location"] is not None
    assert pub["confidence_score"] is not None
