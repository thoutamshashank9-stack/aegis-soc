"""
Comprehensive End-to-End Verification Test Script
Tests scenarios A, B, C, D, E against the live FastAPI endpoint http://127.0.0.1:8000/api/analyze
Verifies:
1. Received headers extraction
2. IP extraction & RFC classification
3. Geolocation handling (public vs non-routable)
4. Absence of fabricated IPs or fake coordinates
5. Evidence preservation (raw headers & hashes)
"""
import requests
import json
import os
import sys

BASE_URL = "http://127.0.0.1:8000/api"
SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "sample_emails"))

def test_scenario(filename, scenario_name, assertions_fn):
    file_path = os.path.join(SAMPLES_DIR, filename)
    print(f"\n=======================================================")
    print(f"RUNNING TEST: {scenario_name} ({filename})")
    print(f"=======================================================")
    
    if not os.path.exists(file_path):
        print(f"ERROR: File {file_path} does not exist!")
        return False
        
    with open(file_path, "rb") as f:
        files = {"file": (filename, f, "message/rfc822")}
        resp = requests.post(f"{BASE_URL}/analyze", files=files)
        
    if resp.status_code != 200:
        print(f"FAILED with HTTP {resp.status_code}: {resp.text}")
        return False
        
    data = resp.json()
    print(f"Status: HTTP 200 OK")
    print(f"Analysis ID: {data.get('id')}")
    print(f"From: {data.get('sender')}")
    print(f"Subject: {data.get('subject')}")
    print(f"SPF: {data.get('authentication', {}).get('spf')}")
    print(f"DKIM: {data.get('authentication', {}).get('dkim')}")
    print(f"DMARC: {data.get('authentication', {}).get('dmarc')}")
    print(f"Extracted IPs count: {len(data.get('ips', []))}")
    print(f"Geolocations count: {len(data.get('geolocations', []))}")
    print(f"Forensic Hops count: {len(data.get('forensic_hops', []))}")
    
    print("\n--- Extracted IP Details ---")
    for ip_rec in data.get("ips", []):
        print(f"  IP: {ip_rec.get('ip')} | Source: {ip_rec.get('source')} | Type: {ip_rec.get('type')}")
        if ip_rec.get('header'):
            print(f"    Raw Header Evidence: {ip_rec.get('header')[:80]}...")
            
    print("\n--- Geolocation Intelligence ---")
    for geo in data.get("geolocations", []):
        print(f"  IP: {geo.get('ip')} | Type: {geo.get('ip_type')} | Public: {geo.get('is_public')}")
        print(f"    Country: {geo.get('country')} | Region: {geo.get('region')} | City: {geo.get('city')}")
        print(f"    ISP: {geo.get('isp')} | ASN: {geo.get('asn')}")
        print(f"    Coordinates: {geo.get('latitude')}, {geo.get('longitude')}")
        if geo.get('not_geolocatable_reason'):
            print(f"    Not Geolocatable Rationale: {geo.get('not_geolocatable_reason')}")
            
    success = assertions_fn(data)
    if success:
        print(f"==> RESULT: [PASSED] {scenario_name}")
    else:
        print(f"==> RESULT: [FAILED] {scenario_name}")
    return success

# Case A Assertions
def assert_case_a(data):
    # No received headers -> 0 hops, 0 IPs from received headers
    assert len(data.get("forensic_hops", [])) == 0, "Expected 0 forensic hops"
    assert len(data.get("geolocations", [])) == 0, "Expected 0 geolocations"
    assert "direct.sender@internal-corp.test" in data.get("sender")
    assert data.get("authentication", {}).get("spf") == "none"
    return True

# Case B Assertions
def assert_case_b(data):
    # RFC 1918 private IP: 10.240.12.88
    geos = data.get("geolocations", [])
    assert len(geos) == 1, f"Expected 1 geolocation, got {len(geos)}"
    g = geos[0]
    assert g.get("ip") == "10.240.12.88", f"Expected IP 10.240.12.88, got {g.get('ip')}"
    assert g.get("ip_type") == "private", f"Expected private type, got {g.get('ip_type')}"
    assert g.get("is_public") is False, "Expected is_public=False"
    assert g.get("latitude") is None, "Expected None latitude for private IP"
    assert g.get("longitude") is None, "Expected None longitude for private IP"
    assert "RFC 1918" in g.get("not_geolocatable_reason", ""), "Expected RFC 1918 in reason"
    assert "10.240.12.88" in g.get("source_header", ""), "Expected raw header evidence"
    return True

# Case C Assertions
def assert_case_c(data):
    # RFC 5737 documentation IP: 198.51.100.42
    geos = data.get("geolocations", [])
    assert len(geos) == 1, f"Expected 1 geolocation, got {len(geos)}"
    g = geos[0]
    assert g.get("ip") == "198.51.100.42", f"Expected IP 198.51.100.42, got {g.get('ip')}"
    assert g.get("ip_type") == "documentation", f"Expected documentation type, got {g.get('ip_type')}"
    assert g.get("is_public") is False, "Expected is_public=False"
    assert g.get("latitude") is None, "Expected None latitude for doc IP"
    assert g.get("longitude") is None, "Expected None longitude for doc IP"
    assert "RFC 5737" in g.get("not_geolocatable_reason", ""), "Expected RFC 5737 in reason"
    assert "198.51.100.42" in g.get("source_header", ""), "Expected raw header evidence"
    return True

# Case D Assertions
def assert_case_d(data):
    # Valid public IP: 8.8.8.8
    geos = data.get("geolocations", [])
    assert len(geos) == 1, f"Expected 1 geolocation, got {len(geos)}"
    g = geos[0]
    assert g.get("ip") == "8.8.8.8", f"Expected IP 8.8.8.8, got {g.get('ip')}"
    assert g.get("ip_type") == "public", f"Expected public type, got {g.get('ip_type')}"
    assert g.get("is_public") is True, "Expected is_public=True"
    assert g.get("country") != "Not geolocatable", "Expected geolocatable country"
    # Live lookup should resolve country and coordinates
    if g.get("lookup_status") == "success":
        assert g.get("latitude") is not None, "Expected latitude for 8.8.8.8"
        assert g.get("longitude") is not None, "Expected longitude for 8.8.8.8"
        assert "Google" in (g.get("isp") or "") or "Google" in (g.get("org") or ""), "Expected Google ISP/Org"
    return True

# Case E Assertions
def assert_case_e(data):
    # Multi-hop: 198.51.100.77 (doc), 1.1.1.1 (public), 172.16.100.5 (private)
    hops = data.get("forensic_hops", [])
    assert len(hops) == 3, f"Expected 3 forensic hops, got {len(hops)}"
    geos = data.get("geolocations", [])
    assert len(geos) == 3, f"Expected 3 extracted IPs, got {len(geos)}"
    
    geo_map = {g["ip"]: g for g in geos}
    assert "198.51.100.77" in geo_map, "Expected 198.51.100.77"
    assert "1.1.1.1" in geo_map, "Expected 1.1.1.1"
    assert "172.16.100.5" in geo_map, "Expected 172.16.100.5"
    
    assert geo_map["198.51.100.77"]["ip_type"] == "documentation", "Expected doc IP"
    assert geo_map["198.51.100.77"]["is_public"] is False
    assert geo_map["198.51.100.77"]["latitude"] is None
    
    assert geo_map["172.16.100.5"]["ip_type"] == "private", "Expected private IP"
    assert geo_map["172.16.100.5"]["is_public"] is False
    assert geo_map["172.16.100.5"]["latitude"] is None
    
    assert geo_map["1.1.1.1"]["ip_type"] == "public", "Expected public IP"
    assert geo_map["1.1.1.1"]["is_public"] is True
    
    # Chronological hop ordering verification
    # RFC 5322 Received headers are bottom-to-top in chronological origin:
    # Origin hop 1 is 198.51.100.77, Hop 2 is 1.1.1.1, Hop 3 is 172.16.100.5
    assert hops[0]["relay_ip"] == "198.51.100.77", f"Hop 1 should be origin, got {hops[0]['relay_ip']}"
    assert hops[1]["relay_ip"] == "1.1.1.1", f"Hop 2 should be cloud relay, got {hops[1]['relay_ip']}"
    assert hops[2]["relay_ip"] == "172.16.100.5", f"Hop 3 should be internal edge, got {hops[2]['relay_ip']}"
    return True

if __name__ == "__main__":
    results = []
    results.append(test_scenario("test_a_no_received_demo.eml", "Case A: No Received Headers", assert_case_a))
    results.append(test_scenario("test_b_private_ip_demo.eml", "Case B: RFC 1918 Private IP", assert_case_b))
    results.append(test_scenario("test_c_documentation_ip_demo.eml", "Case C: RFC 5737 Documentation IP", assert_case_c))
    results.append(test_scenario("test_d_public_ip_demo.eml", "Case D: Routable Public IP (8.8.8.8)", assert_case_d))
    results.append(test_scenario("test_e_multi_hop_demo.eml", "Case E: Multi-Hop Email Traversal", assert_case_e))
    
    print("\n=======================================================")
    print(f"TOTAL TESTS: {len(results)} | PASSED: {sum(results)} | FAILED: {len(results) - sum(results)}")
    print("=======================================================")
    
    if all(results):
        print("ALL VERIFICATION TESTS COMPLETED SUCCESSFULLY!")
        sys.exit(0)
    else:
        print("SOME TESTS FAILED!")
        sys.exit(1)
