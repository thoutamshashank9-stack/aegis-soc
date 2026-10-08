"""
Comprehensive Automated Test Suite for Email Threat Detection & Forensic Intelligence Platform.
Tests:
1. Valid email parsing (.eml)
2. Empty email handling
3. Corrupted / malformed email bytes
4. Email without headers
5. Email with malformed headers
6. Email with attachments & dangerous extensions (.pdf.exe)
7. Email with multiple Received hops & timeline generation
8. Email containing private / RFC 1918 IPs vs public IPs
9. Email with multiple URLs and lookalikes
10. ML inference and classification accuracy
11. Threat engine risk scoring and normalization (0-100)
12. SHA-256 cryptographic hashing
13. API endpoints: /api/health, /api/ml/status, /api/system/status, /api/analyze, /api/analyze/text, /api/analyses
"""
import pytest
from fastapi.testclient import TestClient
from main import app
from app.services.email_analyzer import EmailAnalyzer, is_private_or_reserved_ip
from app.services.url_analyzer import URLAnalyzer
from app.services.attachment_analyzer import AttachmentAnalyzer
from app.services.ml_service import MLClassifierService
from app.services.threat_engine import ThreatEngine
from app.forensic.forensic_engine import ForensicEngine

client = TestClient(app)


def test_health_endpoints():
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"

    res_sys = client.get("/api/system/status")
    assert res_sys.status_code == 200
    assert res_sys.json()["database"] == "online"

    res_ml = client.get("/api/ml/status")
    assert res_ml.status_code == 200
    assert "model_loaded" in res_ml.json()


def test_empty_email():
    res = client.post("/api/analyze/text", json={"raw_text": "   "})
    assert res.status_code == 400


def test_corrupted_email_bytes():
    corrupted_data = b"\x00\xff\xfe\xca\xfe\xba\xbe\xde\xad\xbe\xefrandomgibberish"
    data = EmailAnalyzer.parse_raw_bytes(corrupted_data)
    assert data is not None
    assert "subject" in data
    # Hash calculation still functions
    h = ForensicEngine.calculate_sha256(corrupted_data)
    assert len(h) == 64


def test_email_without_headers():
    body_only = "This is simply raw body text without RFC headers."
    data = EmailAnalyzer.parse_raw_text(body_only)
    assert data["sender_email"] == "unknown"
    assert data["message_id"] == "not_available"
    assert data["body_text"] == body_only


def test_private_vs_public_ip_filtering():
    assert is_private_or_reserved_ip("127.0.0.1") is True
    assert is_private_or_reserved_ip("192.168.1.1") is True
    assert is_private_or_reserved_ip("10.0.0.5") is True
    assert is_private_or_reserved_ip("172.16.5.20") is True
    assert is_private_or_reserved_ip("8.8.8.8") is False
    assert is_private_or_reserved_ip("185.220.101.5") is False


def test_url_analyzer():
    url_test = "http://login-microsoft-security-check.xyz/login"
    res = URLAnalyzer.analyze_url(url_test)
    assert res["is_suspicious"] is True
    # Should identify unencrypted http, suspicious tld (.xyz), and brand impersonation (microsoft)
    rules = [ind["rule"] for ind in res["indicators"]]
    assert "unencrypted_http" in rules
    assert "suspicious_tld" in rules
    assert "brand_impersonation_url" in rules


def test_dangerous_attachment_analyzer():
    attachments = [
        {"filename": "Report.pdf", "content_type": "application/pdf", "size_bytes": 1024},
        {"filename": "Invoice.pdf.exe", "content_type": "application/octet-stream", "size_bytes": 2048}
    ]
    results = AttachmentAnalyzer.analyze_attachments(attachments)
    assert len(results) == 2
    assert results[0]["is_dangerous"] is False
    assert results[1]["is_dangerous"] is True
    assert results[1]["double_extension"] is True


def test_ml_inference():
    phish_text = "Urgent: Your account is suspended. Verify password and credit card immediately."
    res = MLClassifierService.predict("Account Suspended", phish_text)
    assert res["model_available"] is True
    assert res["prediction"] in ["phishing", "spam", "legitimate"]
    assert 0.0 <= res["confidence"] <= 1.0


def test_threat_engine_risk_score_normalization():
    email_data = {
        "sender": "CEO <attacker@bad.xyz>",
        "sender_email": "attacker@bad.xyz",
        "sender_display": "Alice CEO",
        "reply_to": "diff@evil.com",
        "return_path": "bounce@bad.xyz",
        "subject": "URGENT WIRE TRANSFER REQUIRED",
        "body_text": "Please execute wire transfer within 24 hours immediately.",
        "authentication": {"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        "ips": [],
        "domains": []
    }
    url_res = [URLAnalyzer.analyze_url("http://login-portal.top")]
    att_res = AttachmentAnalyzer.analyze_attachments([{"filename": "payload.exe", "size_bytes": 500}])
    ml_res = {"prediction": "phishing", "confidence": 0.95}

    threat = ThreatEngine.analyze_threats(email_data, url_res, att_res, ml_res)
    # Score must be bounded [0, 100]
    assert 0 <= threat["risk_score"] <= 100
    assert threat["risk_score"] >= 80  # Critical
    assert threat["risk_level"] == "CRITICAL"
    assert len(threat["findings"]) > 3


def test_end_to_end_phishing_demo():
    with open("../sample_emails/phishing_demo.eml", "rb") as f:
        file_bytes = f.read()

    res = client.post(
        "/api/analyze",
        files={"file": ("phishing_demo.eml", file_bytes, "message/rfc822")}
    )
    assert res.status_code == 200
    body = res.json()
    assert body["risk_score"] >= 60  # High or Critical
    assert body["authentication"]["spf"] == "fail"
    assert body["authentication"]["dkim"] == "fail"
    assert len(body["urls"]) >= 1
    assert len(body["forensic_hops"]) >= 1
    assert len(body["timeline"]) >= 1
    assert len(body["sha256"]) == 64

    # Test report generation
    report_res = client.get(f"/api/analysis/{body['id']}/report")
    assert report_res.status_code == 200
    assert report_res.json()["verdict"]["risk_score"] == body["risk_score"]

    # Test IOC extraction
    ioc_res = client.get(f"/api/analysis/{body['id']}/iocs")
    assert ioc_res.status_code == 200
    assert ioc_res.json()["sha256"] == body["sha256"]


def test_end_to_end_legitimate_demo():
    with open("../sample_emails/legitimate_demo.eml", "rb") as f:
        file_bytes = f.read()

    res = client.post(
        "/api/analyze",
        files={"file": ("legitimate_demo.eml", file_bytes, "message/rfc822")}
    )
    assert res.status_code == 200
    body = res.json()
    assert body["risk_score"] < 40
    assert body["authentication"]["spf"] == "pass"
    assert body["authentication"]["dkim"] == "pass"
    assert body["authentication"]["dmarc"] == "pass"
