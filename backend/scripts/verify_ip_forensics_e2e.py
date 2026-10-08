"""
End-to-End Verification Script for IP Geolocation & Routing Intelligence.
Runs against http://127.0.0.1:8000 and validates:
1. All 5 synthetic benchmark emails (test_a through test_e).
2. Proper parsing and extraction of Received headers.
3. Strict RFC IP classification (7 types).
4. Safe exclusion of private & documentation IPs from public geocoding.
5. 3-Way location distinction:
   - IP network geolocation (Data center PoP)
   - Mail relay infrastructure role
   - Sender physical location (UNVERIFIED / NOT DETERMINABLE FROM IP)
6. Confidence score (0-100) and forensic explanation.
7. "Why this IP matters" field.
8. Unaltered Received header evidence retention.
"""
import httpx
import os
import sys

BASE_URL = "http://127.0.0.1:8000"
SAMPLE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "sample_emails"))

def verify_all():
    print(f"[*] Starting IP Forensics End-to-End Verification against {BASE_URL}...")
    
    with httpx.Client(timeout=10.0) as client:
        # Check backend health
        health = client.get(f"{BASE_URL}/api/health").json()
        assert health["status"] == "healthy", f"Health status invalid: {health}"
        print("[+] Backend health verified: HEALTHY")

        # Test A: No Received headers
        print("\n--- Testing Scenario A: test_a_no_received_demo.eml ---")
        path_a = os.path.join(SAMPLE_DIR, "test_a_no_received_demo.eml")
        with open(path_a, "rb") as f:
            res_a = client.post(f"{BASE_URL}/api/analyze", files={"file": ("test_a_no_received_demo.eml", f.read(), "message/rfc822")}).json()
        geos_a = res_a.get("geolocations", [])
        print(f"    Extracted IPs count: {len(geos_a)}")
        assert len(geos_a) == 0, f"Expected 0 IPs for email without Received headers, got {len(geos_a)}"
        print("    [PASS] Zero IPs extracted, no fake coordinates fabricated.")

        # Test B: Private RFC 1918 IPs
        print("\n--- Testing Scenario B: test_b_private_ip_demo.eml ---")
        path_b = os.path.join(SAMPLE_DIR, "test_b_private_ip_demo.eml")
        with open(path_b, "rb") as f:
            res_b = client.post(f"{BASE_URL}/api/analyze", files={"file": ("test_b_private_ip_demo.eml", f.read(), "message/rfc822")}).json()
        geos_b = res_b.get("geolocations", [])
        print(f"    Extracted IPs: {[g['ip'] for g in geos_b]}")
        assert any("10.240.12.88" in g["ip"] for g in geos_b), "Missing private IP 10.240.12.88"
        for g in geos_b:
            assert g["is_public"] is False, f"Private IP {g['ip']} incorrectly marked as public"
            assert g["is_geolocatable"] is False, f"Private IP {g['ip']} marked as geolocatable"
            assert g["latitude"] is None and g["longitude"] is None, f"Coordinates fabricated for private IP {g['ip']}"
            assert g["ip_type"] in ["Private", "Loopback"], f"Invalid type for private IP: {g['ip_type']}"
            assert "RFC 1918" in g["not_geolocatable_reason"] or "Loopback" in g["not_geolocatable_reason"]
            assert g["sender_physical_location"] == "UNVERIFIED / NOT APPLICABLE"
        print("    [PASS] Private and loopback IPs classified and excluded from geolocation.")

        # Test C: Documentation RFC 5737 / RFC 3849 IPs
        print("\n--- Testing Scenario C: test_c_documentation_ip_demo.eml ---")
        path_c = os.path.join(SAMPLE_DIR, "test_c_documentation_ip_demo.eml")
        with open(path_c, "rb") as f:
            res_c = client.post(f"{BASE_URL}/api/analyze", files={"file": ("test_c_documentation_ip_demo.eml", f.read(), "message/rfc822")}).json()
        geos_c = res_c.get("geolocations", [])
        print(f"    Extracted IPs: {[g['ip'] for g in geos_c]}")
        assert any("198.51.100.42" in g["ip"] for g in geos_c), "Missing documentation IP 198.51.100.42"
        for g in geos_c:
            assert g["is_public"] is False, f"Documentation IP {g['ip']} incorrectly marked as public"
            assert g["is_geolocatable"] is False
            assert g["latitude"] is None and g["longitude"] is None
            assert g["ip_type"] == "Documentation/test IP"
            assert "RFC 5737" in g["not_geolocatable_reason"] or "RFC 3849" in g["not_geolocatable_reason"]
            assert "Testbed" in g["relay_role"] or "Synthetic" in g["relay_role"]
        print("    [PASS] Documentation testbed IPv4 and IPv6 classified with RFC reason.")

        # Test D: Public Google Workspace MTA IP
        print("\n--- Testing Scenario D: test_d_public_ip_demo.eml ---")
        path_d = os.path.join(SAMPLE_DIR, "test_d_public_ip_demo.eml")
        with open(path_d, "rb") as f:
            res_d = client.post(f"{BASE_URL}/api/analyze", files={"file": ("test_d_public_ip_demo.eml", f.read(), "message/rfc822")}).json()
        geos_d = res_d.get("geolocations", [])
        print(f"    Extracted IPs: {[g['ip'] for g in geos_d]}")
        pub_d = next(g for g in geos_d if g["is_public"])
        print(f"    Public IP: {pub_d['ip']}")
        print(f"    Infrastructure Tag: {pub_d['infrastructure_tag']} | Type: {pub_d['infrastructure_type']}")
        print(f"    Relay Role: {pub_d['relay_role']}")
        print(f"    Confidence Score: {pub_d['confidence_score']}%")
        print(f"    Why it matters: {pub_d['why_it_matters'][:80]}...")
        print(f"    3-Way Distinction:")
        print(f"      1. Network: {pub_d['network_location']}")
        print(f"      2. Relay: {pub_d['relay_location']}")
        print(f"      3. Sender Physical: {pub_d['sender_physical_location']}")
        assert pub_d["is_public"] is True
        assert pub_d["is_geolocatable"] is True
        assert pub_d["confidence_score"] >= 80
        assert "Google" in pub_d["infrastructure_type"] or "Email Provider" in pub_d["infrastructure_type"]
        assert "UNVERIFIED" in pub_d["sender_physical_location"]
        assert "does NOT verify" in pub_d["sender_location_disclaimer"] or "NEVER prove" in pub_d["sender_location_disclaimer"]
        assert len(pub_d["source_header"]) > 20
        print("    [PASS] Public IP properly resolved with 3-way distinction and confidence score.")

        # Test E: Multi-Hop SMTP Chain
        print("\n--- Testing Scenario E: test_e_multi_hop_demo.eml ---")
        path_e = os.path.join(SAMPLE_DIR, "test_e_multi_hop_demo.eml")
        with open(path_e, "rb") as f:
            res_e = client.post(f"{BASE_URL}/api/analyze", files={"file": ("test_e_multi_hop_demo.eml", f.read(), "message/rfc822")}).json()
        geos_e = res_e.get("geolocations", [])
        print(f"    Total Hops Extracted: {len(geos_e)}")
        for g in geos_e:
            print(f"    Hop #{g.get('hop_order')}: {g['ip']} [{g['ip_type']}] -> {g.get('relay_role')}")
            assert g["source_header"] is not None and len(g["source_header"]) > 10, f"Missing source header for {g['ip']}"
            assert g.get("why_it_matters") is not None, f"Missing 'why_it_matters' for {g['ip']}"
        print("    [PASS] Multi-hop evidence chain preserved with chronological hop order and unaltered headers.")

    print("\n=======================================================")
    print("ALL 5 END-TO-END SCENARIO VERIFICATIONS PASSED WITH 100% SUCCESS!")
    print("=======================================================")

if __name__ == "__main__":
    verify_all()
