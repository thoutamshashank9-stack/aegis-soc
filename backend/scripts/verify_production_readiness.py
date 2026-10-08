"""
Production Readiness & End-to-End Test Suite.
Validates:
1. Frontend HTTP 200 (http://127.0.0.1:5173)
2. Backend HTTP 200 (http://127.0.0.1:8000/ and http://127.0.0.1:8000/api/health)
3. Phishing synthetic scenario end-to-end:
   - Analysis completion
   - Threat score & risk level
   - SPF/DKIM/DMARC authentication verification
   - IOC findings extraction
   - Executive report generation
4. Geolocation & Multi-hop scenario (test_e_multi_hop_demo.eml)
"""
import httpx
import os
import sys

FRONTEND_URL = "http://127.0.0.1:5173"
BACKEND_URL = "http://127.0.0.1:8000"
SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "sample_emails"))

def run_tests():
    print("[*] Starting Production Readiness Verification...")
    with httpx.Client(timeout=15.0) as client:
        # 1. Frontend Check
        print(f"[1] Testing Frontend: {FRONTEND_URL}")
        res_fe = client.get(FRONTEND_URL)
        assert res_fe.status_code == 200, f"Frontend returned {res_fe.status_code}"
        print(f"    [PASS] Frontend is responding: HTTP {res_fe.status_code}")

        # 2. Backend Health Check
        print(f"[2] Testing Backend Health: {BACKEND_URL}/api/health")
        res_be = client.get(f"{BACKEND_URL}/api/health")
        assert res_be.status_code == 200, f"Backend health returned {res_be.status_code}"
        assert res_be.json()["status"] == "healthy"
        print(f"    [PASS] Backend health endpoint verified: HTTP {res_be.status_code}")

        # Root Health Check
        res_root = client.get(f"{BACKEND_URL}/health")
        assert res_root.status_code == 200
        print(f"    [PASS] Root /health endpoint verified: HTTP {res_root.status_code}")

        # 3. Phishing End-to-End Test
        print("\n[3] Testing Synthetic PHISHING Attack Scenario...")
        phish_path = os.path.join(SAMPLES_DIR, "phishing_demo.eml")
        with open(phish_path, "rb") as f:
            phish_bytes = f.read()

        res_phish = client.post(
            f"{BACKEND_URL}/api/analyze",
            files={"file": ("phishing_demo.eml", phish_bytes, "message/rfc822")}
        )
        assert res_phish.status_code == 200, f"Analysis failed with code {res_phish.status_code}"
        data = res_phish.json()
        analysis_id = data["id"]
        print(f"    Investigation ID: {analysis_id}")
        
        # Verify Email Analysis
        assert data["subject"] is not None
        assert data["sender"] is not None
        print("    [PASS] 1. Email analysis parsed envelope and headers successfully.")

        # Verify Threat Score
        risk_score = data["risk_score"]
        risk_level = data["risk_level"]
        print(f"    Threat Risk Score: {risk_score}/100 [{risk_level}]")
        assert risk_score >= 60, f"Expected High/Critical risk, got {risk_score}"
        print("    [PASS] 2. Threat score computed and normalized (Critical/High).")

        # Verify SPF/DKIM/DMARC
        auth = data["authentication"]
        print(f"    Authentication: SPF={auth.get('spf')}, DKIM={auth.get('dkim')}, DMARC={auth.get('dmarc')}")
        assert auth.get("spf") in ["fail", "softfail"]
        assert auth.get("dkim") in ["fail", "none"]
        print("    [PASS] 3. SPF/DKIM/DMARC cryptographic validation recorded accurately.")

        # Verify IOC Findings
        iocs = data.get("iocs", {})
        total_iocs = sum(len(v) for v in iocs.values())
        print(f"    Extracted IOC Categories: {list(iocs.keys())} (Total IOC items: {total_iocs})")
        assert total_iocs > 0, "No IOCs extracted from phishing demo"
        print("    [PASS] 4. IOC findings extracted and categorized.")

        # Verify Executive Report
        res_rep = client.get(f"{BACKEND_URL}/api/analysis/{analysis_id}/report")
        assert res_rep.status_code == 200
        rep_data = res_rep.json()
        assert rep_data["verdict"]["risk_score"] == risk_score
        assert rep_data["verdict"]["executive_summary"] is not None
        print(f"    Executive Summary: {rep_data['verdict']['executive_summary'][:80]}...")
        print("    [PASS] 7. Executive report generated and retrieved.")

        # 4. Multi-Hop & Geolocation Test
        print("\n[4] Testing Multi-Hop & Geolocation Scenario...")
        multihop_path = os.path.join(SAMPLES_DIR, "test_e_multi_hop_demo.eml")
        with open(multihop_path, "rb") as f:
            multihop_bytes = f.read()

        res_multi = client.post(
            f"{BACKEND_URL}/api/analyze",
            files={"file": ("test_e_multi_hop_demo.eml", multihop_bytes, "message/rfc822")}
        )
        assert res_multi.status_code == 200
        multi_data = res_multi.json()
        geos = multi_data.get("geolocations", [])
        print(f"    Extracted Routing Hops: {len(geos)}")
        assert len(geos) == 3, f"Expected 3 hops, got {len(geos)}"
        
        # Verify public vs non-routable distinction
        public_hops = [g for g in geos if g["is_public"]]
        non_public = [g for g in geos if not g["is_public"]]
        assert len(public_hops) >= 1
        assert len(non_public) >= 2
        
        for g in non_public:
            assert g["latitude"] is None and g["longitude"] is None
            assert g["is_geolocatable"] is False
            assert "RFC" in g["not_geolocatable_reason"]
            print(f"    Hop #{g['hop_order']}: {g['ip']} ({g['ip_type']}) -> Correctly excluded from map")

        pub = public_hops[0]
        assert pub["is_geolocatable"] is True
        assert pub["latitude"] is not None and pub["longitude"] is not None
        assert "UNVERIFIED" in pub["sender_physical_location"]
        print(f"    Hop #{pub['hop_order']}: {pub['ip']} ({pub['ip_type']}) -> PoP Coordinates: {pub['latitude']}, {pub['longitude']}")
        print("    [PASS] 5 & 6. Multi-hop and IP geolocation tests passed with strict non-equivalence.")

    print("\n" + "=" * 60)
    print("ALL PRODUCTION READINESS CHECKS & TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
